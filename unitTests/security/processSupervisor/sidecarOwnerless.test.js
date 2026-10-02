'use strict';

// After an ops-API restart every thread of the new node adopts the surviving sidecars and none owns one.
// Real worker threads, because the claim is a filesystem race that sequential calls cannot interleave.

const assert = require('node:assert');
const { spawn } = require('node:child_process');
const { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');

const { LONG_RUNNING, failOnSurvivors, reapPidDir, stopQuietly } = require('./reap.js');
const { Worker } = require('node:worker_threads');

const { waitFor } = require('../../waitFor.js');
const { TEST_TIMING, WORKER_MODULES } = require('./helpers.js');
const env = require('#src/utility/environment/environmentManager');
const { fingerprintVersion } = require('#src/security/processSupervisor/sidecarLifecycle');
const { isProcessAlive } = require('#src/security/processSupervisor/processIdentity');
// For its side effect, as at runtime: it stamps the per-boot process instance id every worker inherits
require('#src/components/componentPreparationLock');

const { envPath, termsPath, lifecyclePath, wrapperPath, lockModulePath } = WORKER_MODULES;

const NAME = 'sidecar-ownerless-test';
const THREADS = 8;
const TIMING = TEST_TIMING;
const POLL_MS = 25;
/** A cap on noticing the death, then a settle ten first backoffs long, in which a second restart would show. */
const NOTICE_MS = 5000;
const SETTLE_MS = 10 * TIMING.respawnBaseMs;

/**
 * One thread of a node that inherited a running sidecar: it joins through the PID lock, then reports
 * what it did about the death, which is the whole question.
 */
const script = `
	const { parentPort, workerData } = require('node:worker_threads');
	const env = require(workerData.envPath);
	const terms = require(workerData.termsPath);
	env.initSync();
	env.setProperty(terms.HDB_SETTINGS_NAMES.HDB_ROOT_KEY, workerData.rootPath);
	require(workerData.wrapperPath)._setPollIntervalForTests(workerData.pollMs);
	require(workerData.lockModulePath)._setIdentifyDeadlineForTests(25);
	const { SidecarProcesses, _setTimingForTests } = require(workerData.lifecyclePath);
	_setTimingForTests(workerData.timing);
	const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

	const warnings = [];
	const logger = { info() {}, warn: (line) => warnings.push(String(line)), error: (line) => warnings.push(String(line)) };
	new SidecarProcesses(logger).start(workerData.descriptor).then(
		async (state) => {
			parentPort.postMessage({ phase: 'joined', pid: state.pid, adopted: state.adopted });
			const deadline = Date.now() + workerData.noticeMs;
			// The warning, not state.exited: a restart or a rejoin clears that within one short backoff
			while (!warnings.some((line) => line.includes('has died')) && Date.now() < deadline) await sleep(10);
			// Back on a live pid first, since the restart waits out a keeper's start; the settle then shows a second one
			const joined = state.pid;
			while (!(state.started && state.pid !== undefined && state.pid !== joined) && Date.now() < deadline) await sleep(10);
			parentPort.postMessage({
				phase: 'settled',
				pid: state.pid,
				started: state.started,
				adopted: state.adopted,
				exited: state.exited === true,
				restarts: state.restarts,
				warnings,
			});
		},
		(error) => parentPort.postMessage({ phase: 'failed', error: String((error && error.stack) || error) })
	);
`;

describe('an ownerless sidecar death', function () {
	failOnSurvivors();
	this.timeout(90000);
	let rootPath;
	let pidDir;

	function lockPath() {
		return join(pidDir, `${NAME}.pid`);
	}

	function clear() {
		rmSync(lockPath(), { force: true });
		rmSync(join(pidDir, `${NAME}.sidecar.json`), { force: true });
	}

	let workers = [];

	beforeEach(() => {
		rootPath = env.getHdbBasePath();
		pidDir = join(rootPath, 'pids');
		mkdirSync(pidDir, { recursive: true });
		clear();
		workers = [];
	});

	afterEach(async () => {
		// The threads first, even for a test that timed out: their supervisors would answer the reap with a restart
		await Promise.all(workers.map((worker) => worker.terminate()));
		// The lock names the restarted child even when the test failed before reading it
		reapPidDir(pidDir);
		clear();
	});

	it('CRITICAL: eight threads that all joined it produce exactly one respawn and a live process', async function () {
		if (process.platform === 'win32') this.skip();
		// What an ops-API restart leaves: a live sidecar and a lock naming it, with no thread holding its child
		const inherited = spawn(process.execPath, ['-e', LONG_RUNNING], { stdio: 'ignore' });
		let respawned;
		try {
			await waitFor(() => isProcessAlive(inherited.pid));
			const version = fingerprintVersion('ownerless-v1');
			writeFileSync(lockPath(), `${inherited.pid}\n${version}`);

			const descriptor = {
				name: NAME,
				command: 'node',
				args: ['-e', LONG_RUNNING],
				fingerprint: ['ownerless-v1'],
				reaper: false,
			};
			const workerData = {
				envPath,
				termsPath,
				lifecyclePath,
				rootPath,
				descriptor,
				noticeMs: NOTICE_MS,
				settleMs: SETTLE_MS,
				wrapperPath,
				lockModulePath,
				pollMs: POLL_MS,
				timing: TIMING,
			};

			const joined = [];
			const settled = [];
			const runs = Array.from(
				{ length: THREADS },
				() =>
					new Promise((resolve, reject) => {
						const worker = new Worker(script, { eval: true, workerData });
						workers.push(worker);
						// Harper's thread plumbing posts its own messages on this port; only this test's carry a phase
						worker.on('message', (message) => {
							if (message.phase === 'joined') joined.push(message);
							else if (message.phase === 'settled') {
								settled.push(message);
								resolve(message);
							} else if (message.phase === 'failed') reject(new Error(message.error));
						});
						worker.once('error', reject);
					})
			);

			await waitFor(() => joined.length === THREADS, {
				timeout: 60000,
				interval: 100,
				message: `only ${joined.length} of ${THREADS} threads joined the inherited sidecar`,
			});
			for (const message of joined) {
				assert.strictEqual(message.adopted, true, 'a thread started its own process instead of joining');
				assert.strictEqual(message.pid, inherited.pid, 'a thread joined something other than the inherited pid');
			}
			assert.strictEqual(readFileSync(lockPath(), 'utf-8').split('\n')[0], String(inherited.pid));

			// The death nothing in this node owns: every thread sees it, and exactly one may act
			process.kill(inherited.pid, 'SIGKILL');
			await Promise.all(runs);

			assert.strictEqual(settled.length, THREADS);
			// Not state.exited: the thread that restarts clears it for the incarnation it is about to start
			for (const message of settled) {
				assert.ok(
					message.warnings.some((line) => line.includes('has died')),
					'a thread never noticed the death of the process it joined'
				);
			}
			const restarters = settled.filter((message) => message.restarts > 0);
			assert.strictEqual(
				restarters.length,
				1,
				`${restarters.length} of ${THREADS} threads restarted the sidecar; exactly one may, or the capped backoff is multiplied by the thread count`
			);
			assert.strictEqual(restarters[0].restarts, 1, 'the one restarter took more than one attempt');

			const claims = settled.flatMap((message) =>
				message.warnings.filter((line) => line.includes('claimed its PID lock'))
			);
			assert.strictEqual(claims.length, 1, 'the PID lock was claimed by more than one thread');
			assert.strictEqual(
				settled.flatMap((message) => message.warnings.filter((line) => line.includes('no longer names it'))).length,
				THREADS - 1,
				'a thread that lost the claim did not report the death'
			);

			// The point of the exercise: something is running again, and the lock names it
			assert.strictEqual(existsSync(lockPath()), true, 'the restart left no lock, so the next death is unowned again');
			respawned = Number.parseInt(readFileSync(lockPath(), 'utf-8').split('\n')[0], 10);
			assert.notStrictEqual(respawned, inherited.pid, 'the lock still names the dead process');
			assert.strictEqual(isProcessAlive(respawned), true, 'the lock names a process that is not running');
			assert.strictEqual(restarters[0].pid, respawned, 'the restarter is not the thread holding the running child');
			assert.strictEqual(
				restarters[0].adopted,
				false,
				'the restarter must have started the process, not joined a second wrapper'
			);

			// The seven that stood down answer seven of eight status reads, so they must report the replacement
			const stoodDown = settled.filter((message) => message.restarts === 0);
			assert.strictEqual(stoodDown.length, THREADS - 1);
			for (const message of stoodDown) {
				assert.strictEqual(
					message.pid,
					respawned,
					`a thread that stood down still reports dead pid ${inherited.pid} as the running sidecar`
				);
				assert.strictEqual(message.adopted, true, 'a thread that stood down started its own process');
				assert.strictEqual(message.started, true, 'a thread that stood down reports nothing running');
				assert.strictEqual(
					message.exited,
					false,
					`a thread that stood down still reports dead pid ${inherited.pid} as exited`
				);
			}
		} finally {
			// The threads first, or their supervisors answer these deaths with a restart
			await Promise.all(workers.map((worker) => worker.terminate()));
			stopQuietly(inherited.pid);
			if (respawned) stopQuietly(respawned);
		}
	});
});
