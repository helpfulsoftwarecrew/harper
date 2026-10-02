'use strict';

// The PID lock's identity decisions. A holder identified as something else is never adopted or signalled,
// and one that cannot be identified is never signalled where the platform can identify.

const assert = require('node:assert');
const { execFileSync, spawn } = require('node:child_process');
const { existsSync, lstatSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');
const { Worker } = require('node:worker_threads');

const { waitFor } = require('../../waitFor.js');
const { asAnotherUser } = require('./anotherUser.js');
const {
	LONG_RUNNING,
	failOnSurvivors,
	spawnExecdShell,
	spawnForeign,
	spawnOwnBinary,
	stopQuietly,
} = require('./reap.js');
const {
	acquirePidFileLock,
	acquirePidFileLockAsync,
	commitPidFileLock,
	readPidLock,
	_setIdentifyDeadlineForTests,
} = require('#src/security/processSupervisor/pidFileLock');
const {
	identifyProcess,
	isProcessAlive,
	platformCanIdentifyProcesses,
	startedAt: startTimeOf,
} = require('#src/security/processSupervisor/processIdentity');

// A pid high enough that nothing holds it
const DEAD_PID = 2147483646;

const SHIPPED_IDENTIFY_DEADLINE_MS = 500;

const lockModulePath = require.resolve('#src/security/processSupervisor/pidFileLock');

/** A sibling thread making one call on the lock, which answers with what the call returned. */
function sibling(call, workerData) {
	const script = `
		const { parentPort, workerData } = require('node:worker_threads');
		const lock = require(workerData.lockModulePath);
		parentPort.postMessage((${call})(lock, workerData));
	`;
	const worker = new Worker(script, { eval: true, workerData: { lockModulePath, ...workerData } });
	const answer = new Promise((resolve, reject) => {
		worker.once('message', resolve);
		worker.once('error', reject);
	});
	return { worker, answer };
}

describe('acquirePidFileLock process identity', () => {
	failOnSurvivors();
	let workDir;
	let pidFilePath;

	beforeEach(() => {
		workDir = mkdtempSync(join(tmpdir(), 'pid-file-lock-'));
		pidFilePath = join(workDir, 'agent.pid');
	});

	afterEach(() => {
		rmSync(workDir, { recursive: true, force: true });
	});

	it('reclaims a lock naming a pid nothing holds', () => {
		writeFileSync(pidFilePath, `${DEAD_PID}\n7`);
		const result = acquirePidFileLock(pidFilePath, process.execPath, undefined, 7);
		assert.deepStrictEqual(result, { pid: 0, version: 0 }, 'a dead holder must not be adopted');
		assert.strictEqual(existsSync(pidFilePath), true, 'the lock is re-created for the caller to fill');
	});

	it('NEGATIVE: never adopts or signals a live process that is not the expected command', async function () {
		if (process.platform === 'win32') this.skip();
		const foreign = spawnForeign();
		try {
			await waitFor(() => isProcessAlive(foreign.pid));
			writeFileSync(pidFilePath, `${foreign.pid}\n7`);
			const result = acquirePidFileLock(pidFilePath, process.execPath, undefined, 7);
			assert.deepStrictEqual(result, { pid: 0, version: 0 }, 'a foreign holder was adopted on liveness alone');
			assert.strictEqual(isProcessAlive(foreign.pid), true, 'the lock signalled a process it never identified');
		} finally {
			stopQuietly(foreign.pid);
		}
	});

	it('adopts a holder it cannot identify rather than replacing it', async () => {
		const holder = spawnOwnBinary();
		try {
			await waitFor(() => isProcessAlive(holder.pid));
			writeFileSync(pidFilePath, `${holder.pid}\n7`);
			// An unresolvable expected command answers "cannot tell"; at the same version that is adopted, not reclaimed
			const startedAt = Date.now();
			const result = acquirePidFileLock(pidFilePath, '/nonexistent/agent', undefined, 7);
			assert.deepStrictEqual(result, { pid: holder.pid, version: 7 });
			if (platformCanIdentifyProcesses()) {
				// The shipped deadline, spent in full here because other suites shorten it
				assert.strictEqual(_setIdentifyDeadlineForTests(), SHIPPED_IDENTIFY_DEADLINE_MS);
				assert.ok(Date.now() - startedAt >= SHIPPED_IDENTIFY_DEADLINE_MS, 'adopted before the deadline');
			}
			assert.strictEqual(isProcessAlive(holder.pid), true);
			assert.strictEqual(existsSync(pidFilePath), true, 'a lock that could not be adjudicated must survive');
		} finally {
			stopQuietly(holder.pid);
		}
	});

	it('adopts a positively identified process whose version matches', async () => {
		const child = spawnOwnBinary();
		try {
			await waitFor(() => isProcessAlive(child.pid));
			writeFileSync(pidFilePath, `${child.pid}\n42`);
			const result = acquirePidFileLock(pidFilePath, process.execPath, undefined, 42);
			assert.deepStrictEqual(result, { pid: child.pid, version: 42 });
			assert.strictEqual(isProcessAlive(child.pid), true);
		} finally {
			stopQuietly(child.pid);
		}
	});

	it('restarts a positively identified holder on a version mismatch', async function () {
		this.timeout(10000);
		const child = spawnOwnBinary();
		try {
			await waitFor(() => isProcessAlive(child.pid));
			writeFileSync(pidFilePath, `${child.pid}\n1111`);
			const result = acquirePidFileLock(pidFilePath, process.execPath, undefined, 2222);
			assert.deepStrictEqual(result, { pid: 0, version: 0 });
			await waitFor(() => !isProcessAlive(child.pid), { timeout: 5000 });
		} finally {
			stopQuietly(child.pid);
		}
	});

	it('NEGATIVE: a version mismatch on an unidentified holder adopts instead of killing', async function () {
		// The lock identifies nothing on win32 and keeps the legacy restart there, so this holds on Linux and darwin
		if (!platformCanIdentifyProcesses()) this.skip();
		const holder = spawnOwnBinary();
		try {
			await waitFor(() => isProcessAlive(holder.pid));
			writeFileSync(pidFilePath, `${holder.pid}\n1111`);
			const result = acquirePidFileLock(pidFilePath, '/nonexistent/agent', undefined, 2222);
			assert.deepStrictEqual(result, { pid: holder.pid, version: 1111 });
			assert.strictEqual(isProcessAlive(holder.pid), true, 'an unidentified pid was signalled');
		} finally {
			stopQuietly(holder.pid);
		}
	});

	// The reaper and any node sidecar reach the lock as `process.execPath`, which every node process on
	// the machine answers to. What separates them is the script, so the lock has to weigh that as well.
	it('REGRESSION: never adopts a node process running a different script', async function () {
		if (!platformCanIdentifyProcesses()) this.skip();
		const script = join(workDir, 'sidecar.js');
		writeFileSync(script, LONG_RUNNING);
		const stranger = spawnOwnBinary();
		try {
			await waitFor(() => isProcessAlive(stranger.pid));
			writeFileSync(pidFilePath, `${stranger.pid}\n7`);
			const result = acquirePidFileLock(pidFilePath, process.execPath, script, 7);
			assert.deepStrictEqual(result, { pid: 0, version: 0 }, 'an unrelated node was adopted as this sidecar');
			assert.strictEqual(isProcessAlive(stranger.pid), true, 'and identification must never signal');
		} finally {
			stopQuietly(stranger.pid);
		}
	});

	it('NEGATIVE: a version mismatch never restarts a node running a different script', async function () {
		if (!platformCanIdentifyProcesses()) this.skip();
		const script = join(workDir, 'sidecar.js');
		writeFileSync(script, LONG_RUNNING);
		const stranger = spawnOwnBinary();
		try {
			await waitFor(() => isProcessAlive(stranger.pid));
			// The reaper's case: its lock version fingerprints the boot, so every new node takes the mismatch
			writeFileSync(pidFilePath, `${stranger.pid}\n1111`);
			const result = acquirePidFileLock(pidFilePath, process.execPath, script, 2222);
			assert.deepStrictEqual(result, { pid: 0, version: 0 }, 'the stale lock is reclaimed');
			assert.strictEqual(isProcessAlive(stranger.pid), true, 'a node running another script was signalled');
		} finally {
			stopQuietly(stranger.pid);
		}
	});

	it('adopts the node process that is running the declared script', async function () {
		if (!platformCanIdentifyProcesses()) this.skip();
		const script = join(workDir, 'sidecar.js');
		writeFileSync(script, LONG_RUNNING);
		const child = spawn(process.execPath, [script], { stdio: 'ignore' });
		try {
			await waitFor(() => isProcessAlive(child.pid));
			writeFileSync(pidFilePath, `${child.pid}\n42`);
			const result = acquirePidFileLock(pidFilePath, process.execPath, script, 42);
			assert.deepStrictEqual(result, { pid: child.pid, version: 42 }, 'the sidecar itself must still be joined');
		} finally {
			stopQuietly(child.pid);
		}
	});

	// A sidecar Harper spawned runs as Harper's user, so on Linux a holder this user may not signal or read is not one
	describe("another user's process on Linux", () => {
		let stranger;

		before(async () => {
			stranger = spawnOwnBinary();
			await waitFor(() => isProcessAlive(stranger.pid));
		});

		after(() => stopQuietly(stranger.pid));

		for (const [refused, stub] of [
			['kill(pid, 0) with EPERM', { kill: 'EPERM' }],
			['its executable link with EACCES', { readlink: 'EACCES' }],
		]) {
			it(`reclaims at once, and signals nothing, a lock naming a pid that refuses ${refused}`, async () => {
				for (const script of [undefined, join(workDir, 'sidecar.js')]) {
					writeFileSync(pidFilePath, `${stranger.pid}\n7`);
					const startedAt = Date.now();
					const { result, signals } = await asAnotherUser({ pid: stranger.pid, ...stub }, () =>
						acquirePidFileLock(pidFilePath, process.execPath, script, 8)
					);
					assert.deepStrictEqual(result, { pid: 0, version: 0 }, `another user's process was adopted (${script})`);
					assert.ok(Date.now() - startedAt < SHIPPED_IDENTIFY_DEADLINE_MS, 'the lock waited on a verdict it had');
					assert.deepStrictEqual(signals, [], 'the version change signalled another user');
					assert.strictEqual(isProcessAlive(stranger.pid), true);
				}
			});
		}
	});

	// What a keeper commits: the pid it started, and on line three itself, its command line and the pid's start time
	describe('a lock a keeper committed', () => {
		const STAND_IN = 'setInterval(() => {}, 1 << 30)';

		function kept(pid, record) {
			writeFileSync(
				pidFilePath,
				`${pid}\n7\n${JSON.stringify({ token: 'kept-token', host: process.pid, ...record })}\n`
			);
		}

		it('waits on a dead pid while the keeper it records lives, since that keeper owes the restart', async function () {
			if (!platformCanIdentifyProcesses()) this.skip();
			const keeperArgv = [process.execPath, '-e', STAND_IN, 'keeper-stand-in'];
			const keeper = spawn(keeperArgv[0], keeperArgv.slice(1), { stdio: 'ignore' });
			try {
				await waitFor(() => isProcessAlive(keeper.pid));
				kept(DEAD_PID, { keeper: keeper.pid, keeperArgv });
				const startedAt = Date.now();
				const result = acquirePidFileLock(pidFilePath, process.execPath, undefined, 7, 400);
				assert.ok(
					Date.now() - startedAt >= 400,
					'the lock was taken while its keeper was between a death and a restart'
				);
				assert.deepStrictEqual(result, { pid: 0, version: 0 }, 'past the hard deadline the lock is taken');
			} finally {
				stopQuietly(keeper.pid);
			}
		});

		it('NEGATIVE: reclaims a dead pid at once when the keeper it records is gone', () => {
			kept(DEAD_PID, { keeper: DEAD_PID - 1, keeperArgv: [process.execPath, 'gone'] });
			const startedAt = Date.now();
			const result = acquirePidFileLock(pidFilePath, process.execPath, undefined, 7, 5000);
			assert.deepStrictEqual(result, { pid: 0, version: 0 });
			assert.ok(Date.now() - startedAt < 2000, 'a keeper that is gone was waited on');
		});

		it('adopts a process that exec`d into another program by the start time its keeper recorded', async function () {
			if (!platformCanIdentifyProcesses()) this.skip();
			const child = spawnExecdShell();
			try {
				await waitFor(() => identifyProcess(child.pid, '/bin/sh') === 'differs', { message: 'sh never exec`d' });
				kept(child.pid, { started: startTimeOf(child.pid) });
				const result = acquirePidFileLock(pidFilePath, '/bin/sh', undefined, 7);
				assert.deepStrictEqual(
					result,
					{ pid: child.pid, version: 7 },
					'a kept process was not identified through its exec'
				);
			} finally {
				stopQuietly(child.pid);
			}
		});

		// A recorded start is kernel truth either way: the same binary under a reused pid is not the process it names
		for (const [label, requested] of [
			['at the same version', 7],
			['on a version change', 8],
		]) {
			it(`NEGATIVE: a pid running the same binary with another start time is taken, never adopted or signalled, ${label}`, async function () {
				if (!platformCanIdentifyProcesses()) this.skip();
				const stranger = spawnOwnBinary();
				try {
					await waitFor(() => isProcessAlive(stranger.pid) && startTimeOf(stranger.pid) !== null);
					kept(stranger.pid, { started: 'Thu Jan  1 00:00:00 1970' });
					const result = acquirePidFileLock(pidFilePath, process.execPath, undefined, requested);
					assert.deepStrictEqual(result, { pid: 0, version: 0 }, 'a reused pid was adopted on its binary alone');
					assert.strictEqual(isProcessAlive(stranger.pid), true, 'a reused pid was signalled on its binary alone');
				} finally {
					stopQuietly(stranger.pid);
				}
			});
		}

		it('NEGATIVE: a start time that is not the process`s identifies nothing', async function () {
			if (!platformCanIdentifyProcesses()) this.skip();
			const child = spawnExecdShell();
			try {
				await waitFor(() => identifyProcess(child.pid, '/bin/sh') === 'differs', { message: 'sh never exec`d' });
				kept(child.pid, { started: 'Thu Jan  1 00:00:00 1970' });
				const result = acquirePidFileLock(pidFilePath, '/bin/sh', undefined, 8);
				assert.deepStrictEqual(
					result,
					{ pid: 0, version: 0 },
					'a stranger was adopted on a start time it does not have'
				);
				assert.strictEqual(isProcessAlive(child.pid), true, 'and was signalled');
			} finally {
				stopQuietly(child.pid);
			}
		});
	});

	it('NEGATIVE: a keeper is never taken for the sidecar whose script it carries in its arguments', async function () {
		if (!platformCanIdentifyProcesses()) this.skip();
		const script = join(workDir, 'sidecar.js');
		writeFileSync(script, LONG_RUNNING);
		// A keeper's command line: node, the keeper script, its lock, then the sidecar's own command after `--`
		const keeperLike = spawn(
			process.execPath,
			[
				'-e',
				'setInterval(() => {}, 1 << 30)',
				join(workDir, 'sidecarKeeper.js'),
				'--keep',
				'--lock',
				pidFilePath,
				'--',
				process.execPath,
				script,
			],
			{ stdio: 'ignore' }
		);
		try {
			await waitFor(() => isProcessAlive(keeperLike.pid));
			writeFileSync(pidFilePath, `${keeperLike.pid}\n7`);
			const result = acquirePidFileLock(pidFilePath, process.execPath, script, 8);
			assert.deepStrictEqual(result, { pid: 0, version: 0 }, 'a keeper was adopted as its own sidecar');
			assert.strictEqual(isProcessAlive(keeperLike.pid), true, 'a keeper was signalled as its sidecar');
		} finally {
			stopQuietly(keeperLike.pid);
		}
	});

	it('NEGATIVE: a singleton started for another lock is not this lock`s, however well it matches otherwise', async function () {
		if (!platformCanIdentifyProcesses()) this.skip();
		const script = join(workDir, 'reaper.js');
		writeFileSync(script, LONG_RUNNING);
		const other = spawn(process.execPath, [script, '--self-pid-file', join(workDir, 'other.pid')], { stdio: 'ignore' });
		const ours = spawn(process.execPath, [script, '--self-pid-file', pidFilePath], { stdio: 'ignore' });
		try {
			await waitFor(() => isProcessAlive(other.pid) && isProcessAlive(ours.pid));
			const identity = ['--self-pid-file', pidFilePath];
			writeFileSync(pidFilePath, `${other.pid}\n1111`);
			const reclaimed = acquirePidFileLock(pidFilePath, process.execPath, script, 2222, undefined, undefined, identity);
			assert.deepStrictEqual(reclaimed, { pid: 0, version: 0 }, 'another root`s reaper was taken for this one');
			assert.strictEqual(isProcessAlive(other.pid), true, 'another root`s reaper was signalled on a version change');
			writeFileSync(pidFilePath, `${ours.pid}\n7`);
			const joined = acquirePidFileLock(pidFilePath, process.execPath, script, 7, undefined, undefined, identity);
			assert.deepStrictEqual(joined, { pid: ours.pid, version: 7 }, 'the reaper started for this lock was not joined');
		} finally {
			stopQuietly(other.pid);
			stopQuietly(ours.pid);
		}
	});

	// A claim carries its claimant's pid and start time, so one a dead or restarted node left is told from one in flight
	describe('a claim no keeper has committed', () => {
		const LATER = 'Thu Jan  1 00:00:00 1970';

		it('is written with this process as its claimant, a token, and this process`s start time', async () => {
			const result = await acquirePidFileLockAsync(pidFilePath, process.execPath, undefined, 7);
			assert.strictEqual(result.pid, 0);
			const held = readPidLock(pidFilePath);
			assert.strictEqual(held.claimant, process.pid);
			assert.strictEqual(held.token, result.token);
			if (platformCanIdentifyProcesses()) assert.strictEqual(held.claimantStarted, startTimeOf(process.pid));
		});

		it('left by an earlier process under this pid is taken at once', async function () {
			if (!platformCanIdentifyProcesses()) this.skip();
			writeFileSync(pidFilePath, `\n0\n${process.pid}\nleft-by-an-earlier-node\n${LATER}`);
			const startedAt = Date.now();
			const result = await acquirePidFileLockAsync(pidFilePath, process.execPath, undefined, 7, 5000);
			assert.strictEqual(result.pid, 0);
			assert.ok(Date.now() - startedAt < 2000, 'a claim a restarted node left was waited on as a sibling`s');
			assert.strictEqual(readPidLock(pidFilePath).token, result.token);
		});

		it('whose claimant pid now runs a later process is taken at once', async function () {
			if (!platformCanIdentifyProcesses()) this.skip();
			const stranger = spawnOwnBinary();
			try {
				await waitFor(() => isProcessAlive(stranger.pid) && startTimeOf(stranger.pid) !== null);
				writeFileSync(pidFilePath, `\n0\n${stranger.pid}\nleft-by-a-dead-node\n${LATER}`);
				const startedAt = Date.now();
				const result = acquirePidFileLock(pidFilePath, process.execPath, undefined, 7, 5000);
				assert.deepStrictEqual(result, { pid: 0, version: 0 });
				assert.ok(Date.now() - startedAt < 2000, 'a claim naming a reissued pid was waited on');
			} finally {
				stopQuietly(stranger.pid);
			}
		});

		it('from a live sibling is waited on, then taken over once the claim itself is old rather than thrown on', async () => {
			writeFileSync(pidFilePath, `\n0\n${process.pid}\nin-flight\n${startTimeOf(process.pid) ?? ''}`);
			const startedAt = Date.now();
			const result = await acquirePidFileLockAsync(pidFilePath, process.execPath, undefined, 7, 400);
			assert.ok(Date.now() - startedAt >= 400, 'a claim in flight was taken before it was old');
			assert.strictEqual(result.pid, 0, 'an abandoned claim held the lock for good');
			assert.notStrictEqual(readPidLock(pidFilePath).token, 'in-flight');
		});

		// The caller's own wait says nothing about a claim a sibling wrote a moment ago
		it('NEGATIVE: a caller past its own deadline leaves a sibling`s fresh claim alone until that claim is old', async () => {
			const own = startTimeOf(process.pid) ?? '';
			writeFileSync(pidFilePath, `\n0\n${process.pid}\nfirst\n${own}`);
			const acquiring = acquirePidFileLockAsync(pidFilePath, process.execPath, undefined, 7, 400);
			await delay(300);
			// A sibling takes the first claim over and holds a claim of its own, fresh
			writeFileSync(pidFilePath, `\n0\n${process.pid}\nsecond\n${own}`);
			await delay(250);
			assert.strictEqual(readPidLock(pidFilePath).token, 'second', 'a caller past its own deadline took a fresh claim');
			const result = await acquiring;
			assert.strictEqual(result.pid, 0, 'the claim was never taken once it was old');
		});
	});

	describe('a commit over a claim', () => {
		it('writes only over its own claim, and says whose the lock is otherwise', () => {
			const claim = `\n0\n${process.pid}\nmine\n`;
			writeFileSync(pidFilePath, claim);
			assert.strictEqual(commitPidFileLock(pidFilePath, 'theirs', '4242'), 'taken');
			assert.strictEqual(readFileSync(pidFilePath, 'utf-8'), claim, 'a commit wrote over a claim it did not hold');
			assert.strictEqual(commitPidFileLock(pidFilePath, 'mine', '4242\n7'), 'written');
			assert.strictEqual(readFileSync(pidFilePath, 'utf-8'), '4242\n7');
			rmSync(pidFilePath);
			assert.strictEqual(commitPidFileLock(pidFilePath, 'mine', '4242'), 'gone');
			assert.strictEqual(existsSync(pidFilePath), false, 'a commit recreated a lock that was gone');
		});

		it('NEGATIVE: a commit whose rename fails leaves no temp file behind, as the keeper`s does not', () => {
			const claim = `\n0\n${process.pid}\nmine\n`;
			writeFileSync(pidFilePath, claim);
			const fs = require('node:fs');
			const rename = fs.renameSync;
			fs.renameSync = () => {
				throw Object.assign(new Error('a rename that failed'), { code: 'EIO' });
			};
			try {
				assert.throws(() => commitPidFileLock(pidFilePath, 'mine', '4242'), /a rename that failed/);
			} finally {
				fs.renameSync = rename;
			}
			assert.strictEqual(existsSync(`${pidFilePath}.mine.tmp`), false, 'the failed commit left its temp file');
			assert.strictEqual(readFileSync(pidFilePath, 'utf-8'), claim);
		});
	});

	describe('the gate', () => {
		it('held by a live holder for longer than the lock allows is broken at once', async () => {
			const gate = `${pidFilePath}.claiming`;
			writeFileSync(gate, `${process.pid}\n${startTimeOf(process.pid) ?? ''}`);
			const past = (Date.now() - 60_000) / 1000;
			utimesSync(gate, past, past);
			const startedAt = Date.now();
			const result = await acquirePidFileLockAsync(pidFilePath, process.execPath, undefined, 7, 5000);
			assert.strictEqual(result.pid, 0);
			assert.ok(Date.now() - startedAt < 2000, 'a gate held a minute was waited on as a live one');
		});

		it('NEGATIVE: a caller past its own deadline leaves a live holder`s young gate alone', async () => {
			const gate = `${pidFilePath}.claiming`;
			const holding = `${process.pid}\n${startTimeOf(process.pid) ?? ''}\nsecond`;
			writeFileSync(gate, `${process.pid}\n${startTimeOf(process.pid) ?? ''}\nfirst`);
			const acquiring = acquirePidFileLockAsync(pidFilePath, process.execPath, undefined, 7, 400);
			await delay(300);
			writeFileSync(gate, holding);
			await delay(250);
			assert.strictEqual(readFileSync(gate, 'utf-8'), holding, 'a caller past its own deadline broke a young gate');
			const result = await acquiring;
			assert.strictEqual(result.pid, 0);
		});

		it('left by an earlier process under this pid is broken at once', async function () {
			if (!platformCanIdentifyProcesses()) this.skip();
			writeFileSync(`${pidFilePath}.claiming`, `${process.pid}\nThu Jan  1 00:00:00 1970`);
			const startedAt = Date.now();
			const result = await acquirePidFileLockAsync(pidFilePath, process.execPath, undefined, 7, 5000);
			assert.strictEqual(result.pid, 0);
			assert.ok(Date.now() - startedAt < 2000, 'a gate a restarted node left was waited on');
			assert.strictEqual(existsSync(`${pidFilePath}.claiming`), false);
		});

		it('held by a live sibling until it is old is broken and retaken, not thrown on', async () => {
			writeFileSync(`${pidFilePath}.claiming`, `${process.pid}\n${startTimeOf(process.pid) ?? ''}`);
			const startedAt = Date.now();
			const result = await acquirePidFileLockAsync(pidFilePath, process.execPath, undefined, 7, 400);
			assert.ok(Date.now() - startedAt >= 400, 'a live holder`s gate was broken before it was old');
			assert.strictEqual(result.pid, 0);
		});

		it('a breaker file and a gate a dead thread left are both broken at once', () => {
			writeFileSync(`${pidFilePath}.claiming`, `${DEAD_PID}\n\ngate`);
			writeFileSync(`${pidFilePath}.claiming.breaking`, `${DEAD_PID}\n\nbreaker`);
			const startedAt = Date.now();
			const result = acquirePidFileLock(pidFilePath, process.execPath, undefined, 7, 5000);
			assert.strictEqual(result.pid, 0);
			assert.ok(Date.now() - startedAt < 2000, 'a dead thread`s breaker file was waited on');
			assert.strictEqual(
				existsSync(`${pidFilePath}.claiming.breaking`),
				false,
				'the dead thread`s breaker file was left'
			);
		});

		it('NEGATIVE: a commit whose gate was broken while it wrote leaves the lock to the thread that broke it', async function () {
			if (process.platform === 'win32') this.skip();
			const token = 'stalled';
			const claim = `\n0\n${process.pid}\n${token}\n`;
			writeFileSync(pidFilePath, claim);
			// The committer blocks writing its temp file while it holds the gate, as a holder stalled mid-commit would
			const temp = `${pidFilePath}.${token}.tmp`;
			execFileSync('mkfifo', [temp]);
			const gate = `${pidFilePath}.claiming`;
			const call = sibling((lock, { path, token }) => ({ committed: lock.commitPidFileLock(path, token, '4242') }), {
				path: pidFilePath,
				token,
			});
			try {
				await waitFor(() => existsSync(gate), { message: 'the committer never took the gate' });
				// What a thread that broke the stalled holder's gate leaves: its own gate
				const breaker = `${process.pid}\n${startTimeOf(process.pid) ?? ''}\nbreaker`;
				writeFileSync(gate, breaker);
				readFileSync(temp);
				assert.strictEqual((await call.answer).committed, 'taken', 'a commit wrote after its gate was broken');
				assert.ok(!lstatSync(pidFilePath).isFIFO(), 'the stalled commit renamed its temp file over the lock');
				assert.strictEqual(readFileSync(pidFilePath, 'utf-8'), claim);
				assert.strictEqual(readFileSync(gate, 'utf-8'), breaker, 'the stalled holder removed its breaker`s gate');
				assert.strictEqual(existsSync(temp), false, 'the stalled commit left its temp file');
			} finally {
				await call.worker.terminate();
			}
		});
	});

	it('REGRESSION: a lock recording pid 0 can never signal the caller process group', () => {
		// kill(0) sends to the caller's own group: adopting or restarting "pid 0" is self-termination.
		writeFileSync(pidFilePath, '0\n1');
		const result = acquirePidFileLock(pidFilePath, process.execPath, undefined, 2);
		assert.deepStrictEqual(result, { pid: 0, version: 0 }, 'the garbage lock is reclaimed, nothing signalled');
	});
});
