'use strict';

// A recorded pid can name an unrelated process after a restart, or a zombie; neither is reused or signalled.

const assert = require('node:assert');
const child_process = require('node:child_process');
const { execFileSync, spawn } = child_process;
const { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { Worker } = require('node:worker_threads');
const {
	acquirePidFileLock,
	createSpawn,
	parsePidFile,
	processMatches,
	removeStalePidFile,
	spawnRecord,
} = require('#src/security/jsLoader');
const env = require('#src/utility/environment/environmentManager');
const { CONFIG_PARAMS } = require('#src/utility/hdbTerms');
const { waitFor } = require('../../waitFor.js');

// Far above the pids a test host hands out, so nothing should hold it.
const DEAD_PID = 2 ** 22 - 7;

// A start no live process has: 1 ms after the epoch, and no Linux boot id and start tick.
const STALE_RECORD = '1';

const CHILD_ARGV = [process.execPath, '-e', 'setInterval(function () {}, 1000)'];

const alive = (pid) => {
	try {
		process.kill(pid, 0);
		return true;
	} catch {
		return false;
	}
};

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** The state the OS reports for a pid, 'Z' for a zombie. */
function processState(pid) {
	if (process.platform === 'linux') {
		const stat = readFileSync(`/proc/${pid}/stat`, 'utf-8');
		return stat[stat.lastIndexOf(')') + 2];
	}
	return execFileSync('ps', ['-o', 'state=', '-p', String(pid)], { encoding: 'utf-8' }).trim()[0];
}

/** Spawns `name` through the constrained fork from a worker thread, resolving with the worker and the child's pid. */
async function spawnFromWorker(name, modulePath) {
	const worker = new Worker(
		`const { parentPort, workerData } = require('node:worker_threads');
		require(workerData.initPath);
		const { createSpawn } = require(workerData.jsLoaderPath);
		const fork = createSpawn(require('node:child_process').fork, true);
		const child = fork(workerData.modulePath, [], { name: workerData.name, stdio: 'ignore' });
		parentPort.postMessage({ spawnedPid: child.pid });`,
		{
			eval: true,
			workerData: {
				initPath: require.resolve('../../mocha.init.js'),
				jsLoaderPath: require.resolve('#src/security/jsLoader'),
				modulePath,
				name,
			},
		}
	);
	// Harper's modules post their own startup messages on the same port.
	const pid = await new Promise((resolve, reject) => {
		worker.on('message', (message) => message?.spawnedPid && resolve(message.spawnedPid));
		worker.once('error', reject);
	});
	return { worker, pid };
}

/** A live child with the record createSpawn would write for it, started before each test and killed after. */
function useLiveChild() {
	const state = { pid: 0, record: '' };
	let child;
	beforeEach(() => {
		child = spawn(CHILD_ARGV[0], CHILD_ARGV.slice(1), { stdio: 'ignore' });
		state.pid = child.pid;
		state.record = spawnRecord(child.pid);
	});
	afterEach(() => child.kill('SIGKILL'));
	return state;
}

function useTempDir() {
	const state = { path: '' };
	beforeEach(() => {
		state.path = mkdtempSync(join(tmpdir(), 'harper-pid-identity-'));
	});
	afterEach(() => rmSync(state.path, { recursive: true, force: true }));
	return state;
}

describe('pid file identity', () => {
	describe('parsePidFile', () => {
		it('reads a pid, a version and the recorded start', () => {
			const parsed = parsePidFile('4242\n7\nboot:1234');
			assert.strictEqual(parsed.pid, 4242);
			assert.strictEqual(parsed.version, 7);
			assert.strictEqual(parsed.started, 'boot:1234');
		});

		it('identifies nothing for a file written before the start line existed', () => {
			assert.strictEqual(parsePidFile('4242\n7').started, null);
			assert.strictEqual(parsePidFile('4242').started, null);
		});
	});

	describe('processMatches', () => {
		const child = useLiveChild();

		it('identifies the process its start was recorded for', () => {
			assert.strictEqual(processMatches(child.pid, child.record), true);
		});

		it('NEGATIVE: refuses a live pid whose start is not the one recorded', () => {
			assert.strictEqual(processMatches(child.pid, STALE_RECORD), false);
		});

		it('NEGATIVE: refuses when nothing was recorded, so an old pid file never reuses or signals', () => {
			assert.strictEqual(processMatches(child.pid, null), false);
			assert.strictEqual(processMatches(child.pid, ''), false);
		});

		it('NEGATIVE: refuses a record it cannot read, rather than throwing', () => {
			assert.strictEqual(processMatches(child.pid, 'not a start'), false);
		});

		it('refuses a pid nothing holds', () => {
			assert.strictEqual(processMatches(DEAD_PID, child.record), false);
		});

		it('NEGATIVE: refuses a thread id of this very process, which is the container case', function () {
			if (process.platform !== 'linux') return this.skip();
			const threads = execFileSync('ls', [`/proc/${process.pid}/task`], { encoding: 'utf-8' })
				.split('\n')
				.map(Number)
				.filter((tid) => tid && tid !== process.pid);
			if (threads.length === 0) return this.skip();
			assert.strictEqual(alive(threads[threads.length - 1]), true);
			assert.strictEqual(processMatches(threads[threads.length - 1], child.record), false);
		});
	});

	describe('acquirePidFileLock', () => {
		const child = useLiveChild();
		const dir = useTempDir();
		let pidFile;

		beforeEach(() => {
			pidFile = join(dir.path, 'agent.pid');
		});

		const writePidFile = (version, record) =>
			writeFileSync(pidFile, record === undefined ? `${child.pid}\n${version}` : `${child.pid}\n${version}\n${record}`);

		it('takes the lock when no file exists, and leaves one for the spawn to fill', () => {
			assert.deepStrictEqual(acquirePidFileLock(pidFile, 1), { pid: 0, version: 0 });
			assert.strictEqual(existsSync(pidFile), true);
		});

		it('reuses a pid whose recorded start still matches the running process', () => {
			writePidFile(3, child.record);
			assert.deepStrictEqual(acquirePidFileLock(pidFile, 3), { pid: child.pid, version: 3 });
		});

		it('replaces a file naming a pid nothing holds', () => {
			writeFileSync(pidFile, `${DEAD_PID}\n3\n${child.record}`);
			assert.strictEqual(acquirePidFileLock(pidFile, 3).pid, 0);
		});

		it('NEGATIVE: does not reuse a live pid whose start is not the one recorded', () => {
			writePidFile(3, STALE_RECORD);
			assert.strictEqual(acquirePidFileLock(pidFile, 3).pid, 0);
			assert.strictEqual(alive(child.pid), true);
		});

		it('NEGATIVE: does not reuse a file written before the start line existed', () => {
			writePidFile(3);
			assert.strictEqual(acquirePidFileLock(pidFile, 3).pid, 0);
			assert.strictEqual(alive(child.pid), true);
		});

		it('NEGATIVE: does not signal a pid it could not identify when the version differs', async () => {
			// A SIGTERM is delivered asynchronously, so survival is checked after a second, not at once.
			writePidFile(1, STALE_RECORD);
			assert.strictEqual(acquirePidFileLock(pidFile, 2).pid, 0);
			await wait(1000);
			assert.strictEqual(alive(child.pid), true);
		});

		it('still ends an identified process whose version is not the one asked for', async () => {
			writePidFile(1, child.record);
			assert.strictEqual(acquirePidFileLock(pidFile, 2).pid, 0);
			await waitFor(() => !alive(child.pid), 5000);
		});

		it('breaks a removal guard a killed thread left behind, rather than never taking the lock', () => {
			writeFileSync(pidFile, `${DEAD_PID}\n3\n${child.record}`);
			writeFileSync(`${pidFile}.lock`, '');
			const longAgo = new Date(Date.now() - 60_000);
			utimesSync(pidFile, longAgo, longAgo);
			utimesSync(`${pidFile}.lock`, longAgo, longAgo);
			assert.strictEqual(acquirePidFileLock(pidFile, 3, 10).pid, 0);
			assert.strictEqual(existsSync(`${pidFile}.lock`), false);
		});
	});

	describe('removeStalePidFile', () => {
		const dir = useTempDir();
		let pidFile;

		beforeEach(() => {
			pidFile = join(dir.path, 'agent.pid');
		});

		it('removes a pid file that still holds what was judged stale', () => {
			writeFileSync(pidFile, `${DEAD_PID}\n0\n${STALE_RECORD}`);
			assert.strictEqual(removeStalePidFile(pidFile, `${DEAD_PID}\n0\n${STALE_RECORD}`), true);
			assert.strictEqual(existsSync(pidFile), false);
		});

		it('NEGATIVE: keeps a lock another thread took after this one judged the old file stale', () => {
			writeFileSync(pidFile, '');
			assert.strictEqual(removeStalePidFile(pidFile, `${DEAD_PID}\n0\n${STALE_RECORD}`), false);
			assert.strictEqual(existsSync(pidFile), true);
		});

		it('NEGATIVE: keeps the pid file while another thread holds the removal guard', () => {
			writeFileSync(pidFile, `${DEAD_PID}\n0\n${STALE_RECORD}`);
			writeFileSync(`${pidFile}.lock`, '');
			assert.strictEqual(removeStalePidFile(pidFile, `${DEAD_PID}\n0\n${STALE_RECORD}`), false);
			assert.strictEqual(existsSync(pidFile), true);
			assert.strictEqual(existsSync(`${pidFile}.lock`), true);
		});

		it('NEGATIVE: keeps an empty lock younger than the age asked for, which its owner is still filling', () => {
			writeFileSync(pidFile, '');
			assert.strictEqual(removeStalePidFile(pidFile, '', 100), false);
			assert.strictEqual(existsSync(pidFile), true);
		});
	});

	describe('createSpawn', () => {
		const dir = useTempDir();
		const started = [];
		let configuredSpawnCommands;

		before(() => {
			configuredSpawnCommands = env.get(CONFIG_PARAMS.APPLICATIONS_ALLOWEDSPAWNCOMMANDS);
		});

		after(() => env.setProperty(CONFIG_PARAMS.APPLICATIONS_ALLOWEDSPAWNCOMMANDS, configuredSpawnCommands));

		afterEach(() => {
			for (const handle of started.splice(0)) {
				handle.unref?.();
				try {
					process.kill(handle.pid, 'SIGKILL');
				} catch {
					// Already gone.
				}
			}
		});

		const uniqueName = (shape) => `pid-identity-${shape}-${process.pid}-${Date.now()}`;

		it('reuses the process fork started when the same name is spawned again', () => {
			const modulePath = join(dir.path, 'agent.js');
			writeFileSync(modulePath, 'setInterval(function () {}, 1000);\n');
			const fork = createSpawn(child_process.fork, true);
			const name = uniqueName('fork');
			const first = fork(modulePath, ['run'], { name, stdio: 'ignore' });
			started.push(first);
			const second = fork(modulePath, ['run'], { name, stdio: 'ignore' });
			started.push(second);
			assert.strictEqual(second.pid, first.pid);
		});

		it('reuses a script started through its shebang when the same name is spawned again', function () {
			if (process.platform === 'win32') return this.skip();
			const scriptPath = join(dir.path, 'agent.sh');
			writeFileSync(scriptPath, '#!/bin/sh\nwhile :; do sleep 1; done\n');
			chmodSync(scriptPath, 0o755);
			env.setProperty(CONFIG_PARAMS.APPLICATIONS_ALLOWEDSPAWNCOMMANDS, [scriptPath]);
			const spawnConstrained = createSpawn(child_process.spawn);
			const name = uniqueName('shebang');
			const first = spawnConstrained(scriptPath, ['run'], { name, stdio: 'ignore' });
			started.push(first);
			const second = spawnConstrained(scriptPath, ['run'], { name, stdio: 'ignore' });
			started.push(second);
			assert.strictEqual(second.pid, first.pid);
		});

		it('records the pid, the version and a start that identifies the process', () => {
			const modulePath = join(dir.path, 'agent.js');
			writeFileSync(modulePath, 'setInterval(function () {}, 1000);\n');
			const name = uniqueName('record');
			const first = createSpawn(child_process.fork, true)(modulePath, [], { name, version: 4, stdio: 'ignore' });
			started.push(first);
			const recorded = parsePidFile(readFileSync(join(env.getHdbBasePath(), 'pids', `${name}.pid`), 'utf-8'));
			assert.strictEqual(recorded.pid, first.pid);
			assert.strictEqual(recorded.version, 4);
			assert.strictEqual(processMatches(first.pid, recorded.started), true);
		});

		it('NEGATIVE: starts a new process rather than adopting one that died unreaped after its worker thread ended', async function () {
			if (process.platform !== 'linux' && process.platform !== 'darwin') return this.skip();
			const modulePath = join(dir.path, 'agent.js');
			writeFileSync(modulePath, 'setInterval(function () {}, 1000);\n');
			const name = uniqueName('zombie');
			const { worker, pid: orphanPid } = await spawnFromWorker(name, modulePath);
			await worker.terminate();
			process.kill(orphanPid, 'SIGKILL');
			await waitFor(() => processState(orphanPid) === 'Z', 5000);
			assert.strictEqual(alive(orphanPid), true);
			const next = createSpawn(child_process.fork, true)(modulePath, [], { name, stdio: 'ignore' });
			started.push(next);
			assert.notStrictEqual(next.pid, orphanPid);
			assert.notStrictEqual(processState(next.pid), 'Z');
		});

		it('NEGATIVE: does not leave a wrapper on another thread reading a zombie as running', async function () {
			if (process.platform !== 'linux' && process.platform !== 'darwin') return this.skip();
			const modulePath = join(dir.path, 'agent.js');
			writeFileSync(modulePath, 'setInterval(function () {}, 1000);\n');
			const name = uniqueName('wrapper');
			const { worker, pid: orphanPid } = await spawnFromWorker(name, modulePath);
			const wrapper = createSpawn(child_process.fork, true)(modulePath, [], { name, stdio: 'ignore' });
			started.push(wrapper);
			assert.strictEqual(wrapper.pid, orphanPid);
			let exited = false;
			wrapper.once('exit', () => (exited = true));
			await worker.terminate();
			process.kill(orphanPid, 'SIGKILL');
			await waitFor(() => processState(orphanPid) === 'Z', 5000);
			await waitFor(() => exited, 5000);
			assert.strictEqual(alive(orphanPid), true);
			assert.strictEqual(processState(orphanPid), 'Z');
		});
	});
});
