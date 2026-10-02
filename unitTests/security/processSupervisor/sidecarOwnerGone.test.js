'use strict';

// A sidecar whose starting thread has ended. Node reaps a child, and delivers its exit, only on the event loop
// that spawned it, so these run real worker threads and end the one that called start().

const assert = require('node:assert');
const { existsSync, mkdirSync, readFileSync, rmSync } = require('node:fs');
const { join } = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');
const { Worker } = require('node:worker_threads');

const { waitFor } = require('../../waitFor.js');
const { TEST_TIMING, WORKER_MODULES } = require('./helpers.js');
const { processState } = require('./zombieProcess.js');
const { LONG_RUNNING, failOnSurvivors, reapPidDir } = require('./reap.js');
const env = require('#src/utility/environment/environmentManager');
const { isProcessAlive } = require('#src/security/processSupervisor/processIdentity');
const { readPidLock } = require('#src/security/processSupervisor/pidFileLock');

const { envPath, termsPath, lifecyclePath, wrapperPath, lockModulePath } = WORKER_MODULES;

const TIMING = TEST_TIMING;
const POLL_MS = 25;
/** Ten first backoffs, inside which a restart that should not happen would have begun. */
const NO_RESTART_MS = 10 * TIMING.respawnBaseMs;

/** One thread of a node: it starts or joins the sidecar, and reports what it knows when asked. */
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

	const lines = [];
	const logger = { info: (line) => lines.push(String(line)), warn: (line) => lines.push(String(line)), error: (line) => lines.push(String(line)) };
	let state;
	const processes = new SidecarProcesses(logger);
	processes.start(workerData.descriptor).then(
		(started) => {
			state = started;
			const reaper = processes.reaper?.pid;
			parentPort.postMessage({ phase: 'started', pid: started.pid, adopted: started.adopted, error: started.error, reaper });
		},
		(error) => parentPort.postMessage({ phase: 'failed', error: String((error && error.stack) || error) })
	);
	parentPort.on('message', (message) => {
		if (message !== 'report') return;
		parentPort.postMessage({ phase: 'report', lines, pid: state?.pid, restarts: state?.restarts, exited: state?.exited === true });
	});
`;

describe('a sidecar whose starting thread has ended', function () {
	failOnSurvivors();
	this.timeout(30000);
	if (process.platform === 'win32') return;

	let rootPath;
	let pidDir;
	let workers = [];
	let serial = 0;

	beforeEach(() => {
		rootPath = env.getHdbBasePath();
		pidDir = join(rootPath, 'pids');
		reapPidDir(pidDir);
		rmSync(pidDir, { recursive: true, force: true });
		mkdirSync(pidDir, { recursive: true });
		workers = [];
	});

	afterEach(async () => {
		// The threads first: a supervisor still running answers the reap with a restart
		await Promise.all(workers.map((worker) => worker.terminate()));
		reapPidDir(pidDir);
		rmSync(pidDir, { recursive: true, force: true });
	});

	function descriptor() {
		const name = `sidecar-owner-gone-${++serial}`;
		return { name, command: 'node', args: ['-e', LONG_RUNNING], fingerprint: [name], reaper: false };
	}

	/** A thread that runs start(); resolves once it has, with the thread and what start() returned. */
	function thread(sidecar) {
		const worker = new Worker(script, {
			eval: true,
			workerData: {
				envPath,
				termsPath,
				lifecyclePath,
				wrapperPath,
				lockModulePath,
				rootPath,
				pollMs: POLL_MS,
				timing: TIMING,
				descriptor: sidecar,
			},
		});
		workers.push(worker);
		return new Promise((resolve, reject) => {
			// Harper's thread plumbing posts its own messages on this port; only this suite's carry a phase
			worker.on('message', (message) => {
				if (message.phase === 'started') resolve({ worker, started: message });
				else if (message.phase === 'failed') reject(new Error(message.error));
			});
			worker.once('error', reject);
		});
	}

	function report(worker) {
		return new Promise((resolve) => {
			const listener = (message) => {
				if (message.phase !== 'report') return;
				worker.off('message', listener);
				resolve(message);
			};
			worker.on('message', listener);
			worker.postMessage('report');
		});
	}

	const lockPath = (sidecar) => join(pidDir, `${sidecar.name}.pid`);
	const record = (sidecar) => {
		try {
			return JSON.parse(readFileSync(`${lockPath(sidecar)}.exit`, 'utf-8'));
		} catch {
			return null;
		}
	};

	it('CRITICAL: a crash leaves no zombie of this node behind', async () => {
		const sidecar = descriptor();
		const { worker, started } = await thread(sidecar);
		assert.strictEqual(started.adopted, false, 'the thread must have started the process, not joined one');
		await worker.terminate();
		process.kill(started.pid, 'SIGKILL');
		// Reaped: gone from the table, not a Z row that nothing on this node will ever wait() for
		await waitFor(() => processState(started.pid) === null, {
			timeout: 5000,
			message: `pid ${started.pid} is still a zombie (${processState(started.pid)}) with its starting thread gone`,
		});
	});

	it('CRITICAL: a crash is restarted with no thread left to call anything', async () => {
		const sidecar = descriptor();
		const { worker, started } = await thread(sidecar);
		await worker.terminate();
		process.kill(started.pid, 'SIGKILL');
		const replacement = await waitFor(
			() => {
				const held = readPidLock(lockPath(sidecar));
				return held && held.pid > 0 && held.pid !== started.pid && isProcessAlive(held.pid) ? held.pid : null;
			},
			{ timeout: 10000, message: 'nothing restarted a crash once the thread that started it had ended' }
		);
		assert.strictEqual(record(sidecar)?.outcome, 'restarting');
		process.kill(replacement, 'SIGTERM');
	});

	// The reaper stops these once the node is gone, so its own death needs a parent that outlives the thread
	it('CRITICAL: a reaper killed once its thread has ended is reaped and started again', async () => {
		const { worker, started } = await thread({ ...descriptor(), reaper: true });
		assert.ok(started.reaper > 0, 'no reaper was launched');
		await worker.terminate();
		process.kill(started.reaper, 'SIGKILL');
		await waitFor(() => processState(started.reaper) === null, {
			timeout: 5000,
			message: `reaper ${started.reaper} is still a zombie (${processState(started.reaper)}) with its thread gone`,
		});
		await waitFor(
			() => {
				const held = readPidLock(join(pidDir, 'harper-sidecar-reaper.pid'));
				return held && held.pid > 0 && held.pid !== started.reaper && isProcessAlive(held.pid);
			},
			{ timeout: 10000, message: 'nothing restarted the reaper once the thread that launched it had ended' }
		);
	});

	it('NEGATIVE: a deliberate stop is not restarted by a thread that only joined', async () => {
		const sidecar = descriptor();
		const owner = await thread(sidecar);
		const joiner = await thread(sidecar);
		assert.strictEqual(joiner.started.adopted, true, 'the second thread must join, not start a second process');
		assert.strictEqual(joiner.started.pid, owner.started.pid);
		await owner.worker.terminate();

		process.kill(owner.started.pid, 'SIGTERM');
		await waitFor(async () => (await report(joiner.worker)).exited, {
			timeout: 5000,
			message: 'the thread that joined never noticed the death',
		});
		await delay(NO_RESTART_MS);
		const seen = await report(joiner.worker);
		assert.strictEqual(
			seen.restarts,
			0,
			`a joined thread restarted a process stopped with SIGTERM: ${seen.lines.join(' | ')}`
		);
		assert.ok(!seen.lines.some((line) => line.includes('claimed its PID lock')), 'a joined thread claimed the stop');
		assert.strictEqual(existsSync(lockPath(sidecar)), false, 'something started the process again');
		assert.strictEqual(record(sidecar)?.outcome, 'released');
		assert.ok(
			seen.lines.some((line) => line.includes('was terminated by SIGTERM')),
			seen.lines.join(' | ')
		);
	});
});
