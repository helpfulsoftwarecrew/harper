'use strict';

// Real worker threads claiming one PID lock, because sequential calls cannot produce these interleavings.
// Exactly one may be told to spawn, and every other thread must be handed the winner's pid to adopt.

const assert = require('node:assert');
const { spawn } = require('node:child_process');
const { existsSync, mkdtempSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { Worker } = require('node:worker_threads');

const { waitFor } = require('../../waitFor.js');
const { failOnSurvivors, reapPidDir, stopQuietly } = require('./reap.js');
const { isProcessAlive } = require('#src/security/processSupervisor/processIdentity');

const lockModulePath = require.resolve('#src/security/processSupervisor/pidFileLock');
// pidFileLock loads Harper's logger, which binds to ROOTPATH on first load (mocha.init.js header), so a bare
// worker runs mocha's bootstrap before the lock.
const initPath = require.resolve('../../mocha.init.js');

// A binary with no script argument, so identifyProcess can answer 'match' on the executable alone.
const SLEEP = existsSync('/bin/sleep') ? '/bin/sleep' : '/usr/bin/sleep';
const DEAD_PID = 2147483646;

// A start gate: workers spawned in a loop boot one after another, so without it the first finishes before
// the second has loaded and nothing races. Each parks on the shared word once loaded, and all go when it flips.
const script = `
	const { parentPort, workerData } = require('node:worker_threads');
	require(workerData.initPath);
	const { acquirePidFileLock } = require(workerData.lockModulePath);
	const { lockPath, command, version, gate } = workerData;
	const go = new Int32Array(gate);
	parentPort.postMessage({ ready: true });
	while (Atomics.load(go, 0) === 0) Atomics.wait(go, 0, 0, 20);
	try {
		const held = acquirePidFileLock(lockPath, command, undefined, version);
		// Name the holder as createSpawn names its child; this worker's own pid runs node, so every thread would take the lock
		if (held.pid === 0) require('node:fs').writeFileSync(lockPath, workerData.holderPid + '\\n' + version);
		parentPort.postMessage({ race: true, held });
	} catch (error) {
		parentPort.postMessage({ race: true, error: error.message });
	}
`;

function claimant(lockPath, sidecar, gate, onReady) {
	return new Promise((resolve, reject) => {
		const worker = new Worker(script, {
			eval: true,
			workerData: { lockModulePath, initPath, lockPath, gate, ...sidecar },
		});
		// Harper's own bootstrap posts child_startup_phase on this port, so a bare once('message')
		// resolves with the runtime's chatter rather than the claim.
		worker.on('message', (message) => {
			if (message?.ready) onReady();
			if (message?.race) resolve(message);
		});
		worker.once('error', reject);
	});
}

describe('pid lock claim race', function () {
	failOnSurvivors();
	this.timeout(60000);
	let pidDir;

	beforeEach(() => {
		pidDir = mkdtempSync(join(tmpdir(), 'lock-race-'));
	});

	afterEach(() => {
		// The locks and descriptors are the only record of what this test started, so reap before removing them
		reapPidDir(pidDir);
		rmSync(pidDir, { recursive: true, force: true });
	});

	it('CRITICAL: sixteen threads on one dead lock, and exactly one is told to spawn', async () => {
		const lockPath = join(pidDir, 'alpha-agent.pid');
		writeFileSync(lockPath, `${DEAD_PID}\n1`);
		// The expected command, so the holder identifies as a match; a holder running any other program is taken, not adopted
		const holder = spawn(SLEEP, ['600'], { stdio: 'ignore' });
		try {
			await waitFor(() => isProcessAlive(holder.pid));

			const gate = new SharedArrayBuffer(4);
			let ready = 0;
			const work = [];
			for (let i = 0; i < 16; i++)
				work.push(claimant(lockPath, { command: SLEEP, version: 1, holderPid: holder.pid }, gate, () => ready++));
			await waitFor(() => ready === 16, { timeout: 30000, message: `only ${ready} of 16 threads loaded the lock` });
			Atomics.store(new Int32Array(gate), 0, 1);
			Atomics.notify(new Int32Array(gate), 0);
			const results = await Promise.all(work);

			for (const result of results) assert.strictEqual(result.error, undefined, `a thread failed: ${result.error}`);
			assert.ok(results[0].held, `no thread returned a lock: ${JSON.stringify(results[0])}`);
			// pid 0 is "the lock is yours, go spawn". More than one is two processes under one name.
			const toSpawn = results.filter((result) => result.held.pid === 0);
			assert.strictEqual(toSpawn.length, 1, `${toSpawn.length} threads were told to spawn, and exactly one may`);
			// And the rest adopted the holder rather than something else.
			for (const result of results.filter((r) => r.held.pid !== 0))
				assert.strictEqual(result.held.pid, holder.pid, 'a thread adopted a pid nobody claimed');
			assert.strictEqual(isProcessAlive(holder.pid), true, 'a claimant signalled the process it should adopt');
		} finally {
			stopQuietly(holder.pid);
		}
	});

	// Adoption is a read, not an arbitration, so it is covered single-threaded in pidFileLock.test.js
});
