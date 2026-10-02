'use strict';

// The wrapper a joining thread holds: its liveness poll is that thread's only notice of a death, so unref
// must release the event loop and not the watch, and the poll must read a corpse as dead.

const assert = require('node:assert');
const { spawn } = require('node:child_process');
const { existsSync, mkdirSync, rmSync, writeFileSync } = require('node:fs');
const { dirname, join } = require('node:path');

const { waitFor } = require('../../waitFor.js');
const { processState } = require('./zombieProcess.js');
const { LONG_RUNNING, failOnSurvivors, stopQuietly, track } = require('./reap.js');
const env = require('#src/utility/environment/environmentManager');
const { child_processConstrained } = require('#src/security/processSupervisor/constrainedChildProcess');
const getConstrainedSpawn = () => child_processConstrained.spawn;
const { _setPollIntervalForTests } = require('#src/security/processSupervisor/adoptionWrapper');
const { _setIdentifyDeadlineForTests } = require('#src/security/processSupervisor/pidFileLock');
const { isProcessAlive } = require('#src/security/processSupervisor/processIdentity');

const OWNED_NAME = 'adoption-wrapper-test';
const ZOMBIE_NAME = 'adoption-wrapper-zombie-test';
// darwin reads the process state every tenth poll, so a zombie takes up to ten polls to be noticed
const POLL_MS = 25;
const ZOMBIE_NOTICE_MS = 5000;

describe('the adoption wrapper', function () {
	failOnSurvivors();
	this.timeout(20000);
	let pidDir;

	before(() => {
		_setPollIntervalForTests(POLL_MS);
		_setIdentifyDeadlineForTests(25);
	});
	after(() => {
		_setPollIntervalForTests();
		_setIdentifyDeadlineForTests();
	});

	function lockPath(name) {
		return join(pidDir, `${name}.pid`);
	}

	function clearLocks() {
		rmSync(lockPath(OWNED_NAME), { force: true });
		rmSync(lockPath(ZOMBIE_NAME), { force: true });
	}

	beforeEach(() => {
		pidDir = join(env.getHdbBasePath(), 'pids');
		clearLocks();
	});

	afterEach(clearLocks);

	it('ships a one-second poll, which this suite shortens', () => {
		try {
			assert.strictEqual(_setPollIntervalForTests(), 1000);
		} finally {
			_setPollIntervalForTests(POLL_MS);
		}
	});

	it('REGRESSION: unref leaves the wrapper reporting the death it exists to report', async () => {
		const spawnLocked = getConstrainedSpawn();
		const options = { name: OWNED_NAME, stdio: ['ignore', 'ignore', 'ignore'], env: process.env };
		const owner = spawnLocked('node', ['-e', LONG_RUNNING], options);
		try {
			assert.ok(Array.isArray(owner.spawnargs), 'the first spawn must win the lock and hold a real child');
			assert.strictEqual(existsSync(lockPath(OWNED_NAME)), true);

			const joiner = spawnLocked('node', ['-e', LONG_RUNNING], options);
			assert.strictEqual(Array.isArray(joiner.spawnargs), false, 'the second spawn must be handed the wrapper');
			assert.strictEqual(joiner.pid, owner.pid, 'and must join the running process, not start a second one');

			// What every caller does with a joined process
			joiner.unref();
			let exits = 0;
			joiner.on('exit', () => (exits += 1));

			process.kill(owner.pid, 'SIGKILL');
			await waitFor(() => exits === 1, { timeout: 5000, message: 'the wrapper never reported the death' });
		} finally {
			stopQuietly(owner.pid);
		}
	});

	it('CRITICAL: reports a joined process that died into a zombie nothing reaps', async function () {
		if (process.platform !== 'linux' && process.platform !== 'darwin') this.skip();
		// sh execs in place without wait()ing, so its killed child stays unreaped, as under a non-reaping init
		const holder = spawn('/bin/sh', ['-c', 'sleep 600 & echo $!; exec sleep 3600'], {
			stdio: ['ignore', 'pipe', 'ignore'],
		});
		let output = '';
		holder.stdout.on('data', (chunk) => (output += chunk));
		let target;
		try {
			target = Number.parseInt(String(await waitFor(() => output.trim())), 10);
			track(target);
			await waitFor(() => isProcessAlive(target));

			// A bare command name identifies as "cannot tell", so the lock joins this process rather than replacing it
			mkdirSync(dirname(lockPath(ZOMBIE_NAME)), { recursive: true });
			writeFileSync(lockPath(ZOMBIE_NAME), `${target}\n0`);
			const joiner = getConstrainedSpawn()('node', ['-e', LONG_RUNNING], {
				name: ZOMBIE_NAME,
				stdio: ['ignore', 'ignore', 'ignore'],
				env: process.env,
			});
			assert.strictEqual(Array.isArray(joiner.spawnargs), false, 'the lock must hand back the wrapper');
			assert.strictEqual(joiner.pid, target);
			joiner.unref();
			let exits = 0;
			joiner.on('exit', () => (exits += 1));

			process.kill(target, 'SIGKILL');
			await waitFor(() => processState(target) === 'Z', { message: `pid ${target} never turned zombie` });
			assert.doesNotThrow(() => process.kill(target, 0), 'the blind spot: kill(pid, 0) still answers for a corpse');

			await waitFor(() => exits === 1, {
				timeout: ZOMBIE_NOTICE_MS,
				interval: 100,
				message: 'the wrapper read a corpse as alive',
			});
		} finally {
			// The target first: its parent's death would leave it running under pid 1
			if (target) stopQuietly(target);
			holder.kill('SIGKILL');
		}
	});
});
