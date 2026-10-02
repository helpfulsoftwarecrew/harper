'use strict';

// Who gets to restart a process whose death a thread observed without owning it. Two properties: the
// claim is refused unless the lock still names that dead pid, and at most one racing thread wins it.

const assert = require('node:assert');
const { spawn } = require('node:child_process');
const { existsSync, mkdtempSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { Worker } = require('node:worker_threads');

const { waitFor } = require('../../waitFor.js');
const { failOnSurvivors, spawnOwnBinary, stopQuietly } = require('./reap.js');
const { _setClaimGateWaitForTests, claimDeadPidFileLock } = require('#src/security/processSupervisor/pidLockClaim');
const { isProcessAlive, startedAt } = require('#src/security/processSupervisor/processIdentity');

// A pid high enough that nothing holds it
const DEAD_PID = 2147483646;
/** Enough races that a claim which is not a test-and-set is caught rather than merely likely to be. */
const CLAIM_RACE_ROUNDS = 100;

const claimModulePath = require.resolve('#src/security/processSupervisor/pidLockClaim');

/**
 * Threads parked on one shared word, so a round releases them together rather than staggering them by
 * worker startup. Each answers with what the claim told it about that round's lock.
 */
const raceScript = `
	const { parentPort, workerData } = require('node:worker_threads');
	const { claimDeadPidFileLock } = require(workerData.claimModulePath);
	const gate = new Int32Array(workerData.gate);
	parentPort.on('message', ({ path, deadPid, round }) => {
		while (Atomics.load(gate, 0) !== round) Atomics.wait(gate, 0, Atomics.load(gate, 0), 50);
		parentPort.postMessage({ claimed: claimDeadPidFileLock(path, deadPid) });
	});
	parentPort.postMessage({ ready: true });
`;

async function startClaimRace(count) {
	const gate = new SharedArrayBuffer(4);
	const view = new Int32Array(gate);
	const workers = [];
	let failure;
	await Promise.all(
		Array.from(
			{ length: count },
			() =>
				new Promise((resolve, reject) => {
					const worker = new Worker(raceScript, { eval: true, workerData: { claimModulePath, gate } });
					workers.push(worker);
					// Attached once, not per round: a per-round listener would pile up across a hundred races
					worker.on('error', (error) => {
						failure = error;
						reject(error);
					});
					worker.once('message', resolve);
				})
		)
	);
	const race = async (path, round) => {
		const answers = workers.map((worker) => new Promise((resolve) => worker.once('message', resolve)));
		for (const worker of workers) worker.postMessage({ path, deadPid: DEAD_PID, round });
		Atomics.store(view, 0, round);
		Atomics.notify(view, 0);
		const messages = await Promise.all(answers);
		if (failure) throw failure;
		return messages.map((message) => message.claimed);
	};
	return { workers, race };
}

describe('claimDeadPidFileLock', () => {
	failOnSurvivors();
	let workDir;
	let pidFilePath;

	beforeEach(() => {
		workDir = mkdtempSync(join(tmpdir(), 'pid-file-claim-'));
		pidFilePath = join(workDir, 'agent.pid');
	});

	afterEach(() => {
		rmSync(workDir, { recursive: true, force: true });
	});

	it('claims a lock that still names the dead process, and takes it away', () => {
		writeFileSync(pidFilePath, `${DEAD_PID}\n7`);
		assert.strictEqual(claimDeadPidFileLock(pidFilePath, DEAD_PID), true);
		assert.strictEqual(existsSync(pidFilePath), false, 'the claim must remove the lock it claimed');
	});

	it('a second sequential caller finds nothing left to claim', () => {
		writeFileSync(pidFilePath, `${DEAD_PID}\n7`);
		const claims = Array.from({ length: 8 }, () => claimDeadPidFileLock(pidFilePath, DEAD_PID));
		assert.deepStrictEqual(
			claims,
			[true, false, false, false, false, false, false, false],
			'more than one caller claimed a single death, which is what multiplies the capped backoff'
		);
	});

	it('NEGATIVE: refuses when the lock is already gone, which is what a deliberate stop leaves', () => {
		// The shutdown stop removes the lock before its SIGTERM, and an owner removes it on the exit event
		assert.strictEqual(claimDeadPidFileLock(pidFilePath, DEAD_PID), false);
	});

	it('NEGATIVE: refuses a lock that has been replaced, and signals nothing', async function () {
		if (process.platform === 'win32') this.skip();
		const replacement = spawnOwnBinary();
		try {
			await waitFor(() => isProcessAlive(replacement.pid));
			writeFileSync(pidFilePath, `${replacement.pid}\n7`);
			assert.strictEqual(claimDeadPidFileLock(pidFilePath, DEAD_PID), false, 'a lock naming another pid was claimed');
			assert.strictEqual(existsSync(pidFilePath), true, 'the replacement lock was removed');
			// The number the caller watched has been reused: nothing here is the caller's to remove
			writeFileSync(pidFilePath, `${replacement.pid}\n7`);
			assert.strictEqual(claimDeadPidFileLock(pidFilePath, replacement.pid), false);
			assert.strictEqual(isProcessAlive(replacement.pid), true, 'the claim signalled a process');
		} finally {
			stopQuietly(replacement.pid);
		}
	});

	it('NEGATIVE: refuses a death whose lock records a keeper still running, since the keeper restarts it', async function () {
		if (process.platform === 'win32') this.skip();
		const keeperArgv = [process.execPath, '-e', 'setInterval(() => {}, 1 << 30)', 'keeper-stand-in'];
		const keeper = spawn(keeperArgv[0], keeperArgv.slice(1), { stdio: 'ignore' });
		try {
			await waitFor(() => isProcessAlive(keeper.pid));
			const record = (pid) => JSON.stringify({ token: 'kept-token', host: process.pid, keeper: pid, keeperArgv });
			writeFileSync(pidFilePath, `${DEAD_PID}\n7\n${record(keeper.pid)}\n`);
			assert.strictEqual(claimDeadPidFileLock(pidFilePath, DEAD_PID), false, 'a death its keeper owes was claimed');
			assert.strictEqual(existsSync(pidFilePath), true, 'the keeper`s lock was taken away from it');
			// The same lock once its keeper is gone is an ordinary ownerless death
			writeFileSync(pidFilePath, `${DEAD_PID}\n7\n${record(DEAD_PID - 1)}\n`);
			assert.strictEqual(claimDeadPidFileLock(pidFilePath, DEAD_PID), true);
		} finally {
			stopQuietly(keeper.pid);
		}
	});

	it('NEGATIVE: decides under the lock`s gate, so a thread holding it keeps the lock from the claim', () => {
		writeFileSync(pidFilePath, `${DEAD_PID}\n7`);
		// A sibling deciding this lock right now, which may be writing its own claim over the dead pid
		const gate = `${pidFilePath}.claiming`;
		writeFileSync(gate, `${process.pid}\n${startedAt(process.pid) ?? ''}\nsibling`);
		assert.strictEqual(_setClaimGateWaitForTests(200), 200);
		try {
			assert.strictEqual(claimDeadPidFileLock(pidFilePath, DEAD_PID), false, 'a death was claimed through a held gate');
		} finally {
			assert.strictEqual(_setClaimGateWaitForTests(), 2000, 'the shipped wait on a held gate');
		}
		assert.strictEqual(existsSync(pidFilePath), true, 'the claim removed a lock a sibling was deciding');
		rmSync(gate);
		assert.strictEqual(claimDeadPidFileLock(pidFilePath, DEAD_PID), true, 'the claim failed once the gate was free');
	});

	it('NEGATIVE: refuses the pids that are process-group selectors to kill(2)', () => {
		for (const pid of [0, -1, 1.5, Number.NaN]) {
			writeFileSync(pidFilePath, `${pid}\n7`);
			assert.strictEqual(claimDeadPidFileLock(pidFilePath, pid), false, `pid ${pid} was claimable`);
		}
		assert.strictEqual(existsSync(pidFilePath), true);
	});

	it('CRITICAL: eight threads released together on one death produce exactly one claim', async function () {
		this.timeout(120000);
		// Sequential calls cannot bind this: concurrent unlinks of one name can each report success
		const { workers, race } = await startClaimRace(8);
		try {
			for (let round = 1; round <= CLAIM_RACE_ROUNDS; round++) {
				const path = join(workDir, `race-${round}.pid`);
				writeFileSync(path, `${DEAD_PID}\n7`);
				const claimed = (await race(path, round)).filter(Boolean).length;
				assert.strictEqual(
					claimed,
					1,
					`round ${round}: ${claimed} threads claimed one death, and exactly one may, or the capped backoff is multiplied by the thread count`
				);
				assert.strictEqual(existsSync(path), false, `round ${round}: the claim left the lock behind`);
			}
		} finally {
			await Promise.all(workers.map((worker) => worker.terminate()));
		}
	});
});
