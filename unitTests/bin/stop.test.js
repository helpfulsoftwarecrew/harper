'use strict';

const assert = require('node:assert');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');

const env = require('#src/utility/environment/environmentManager');
const hdbTerms = require('#src/utility/hdbTerms');
const systemInformation = require('#src/utility/environment/systemInformation');
const { isProcessRunning } = require('#js/utility/processManagement/processManagement');
const { default: stop, removeIfStillNames } = require('#src/bin/stop');
const { waitFor } = require('../waitFor.js');
const { makeZombie } = require('../zombieProcess.js');

describe('harper stop identifies the process hdb.pid names', function () {
	let originalRoot;
	let root;
	let pidFile;

	before(function () {
		// kill(1) through a shell and the sleep and zombie holders are POSIX only
		if (process.platform !== 'linux' && process.platform !== 'darwin') this.skip();
		originalRoot = env.get(hdbTerms.CONFIG_PARAMS.ROOTPATH);
		root = fs.mkdtempSync(path.join(os.tmpdir(), 'harper-stop-test-'));
		pidFile = path.join(root, hdbTerms.HDB_PID_FILE);
	});

	after(() => {
		if (root === undefined) return;
		env.setProperty(hdbTerms.CONFIG_PARAMS.ROOTPATH, originalRoot);
		fs.rmSync(root, { force: true, recursive: true });
	});

	async function stopWithPidFile(pid) {
		env.setProperty(hdbTerms.CONFIG_PARAMS.ROOTPATH, root);
		fs.writeFileSync(pidFile, `${pid}\n`);
		// systeminformation reuses its process list for 500 ms on Linux, so wait until it lists the holder
		await waitFor(async () => (await systemInformation.getHDBProcessInfo()).core.some((p) => p.pid === pid), {
			message: `the process list never showed pid ${pid}`,
		});
		const log = console.log;
		const printed = [];
		console.log = (...args) => printed.push(args.join(' '));
		try {
			await stop();
		} finally {
			console.log = log;
		}
		return printed.join('\n');
	}

	it('NEGATIVE: never signals a live process that hdb.pid names but is not Harper, and removes the file', async () => {
		const stranger = spawn('sleep', ['600'], { stdio: 'ignore' });
		let exited = false;
		stranger.on('exit', () => (exited = true));
		try {
			await waitFor(() => isProcessRunning(stranger.pid));
			const printed = await stopWithPidFile(stranger.pid);
			// A non-event: a kill(1) from stop lands within milliseconds, so a second without an exit is its absence
			await delay(1000);
			assert.equal(exited, false, 'harper stop signalled a process that is not Harper');
			assert.equal(isProcessRunning(stranger.pid), true);
			assert.equal(fs.existsSync(pidFile), false, 'the stale pid file stays');
			assert.match(
				printed,
				new RegExp(`Not signalling pid ${stranger.pid} .*not Harper\\. Removed the stale pid file\\.`)
			);
		} finally {
			stranger.kill('SIGKILL');
		}
	});

	it('removes a pid file naming a dead-but-unreaped zombie and says so', async () => {
		const { zombiePid, release } = await makeZombie();
		try {
			const printed = await stopWithPidFile(zombiePid);
			assert.equal(fs.existsSync(pidFile), false, 'the stale pid file stays');
			assert.match(
				printed,
				new RegExp(`Not signalling pid ${zombiePid} .*is not running\\. Removed the stale pid file\\.`)
			);
		} finally {
			release();
		}
	});

	it('still signals a live process of this runtime, which may be the Harper to stop', async () => {
		const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1 << 30)'], { stdio: 'ignore' });
		let exitSignal;
		child.on('exit', (code, signal) => (exitSignal = signal));
		try {
			await waitFor(() => isProcessRunning(child.pid));
			const printed = await stopWithPidFile(child.pid);
			await waitFor(() => exitSignal, { message: 'harper stop did not signal a live node holding the pid' });
			assert.equal(exitSignal, 'SIGTERM');
			assert.doesNotMatch(printed, /Not signalling/);
		} finally {
			child.kill('SIGKILL');
			fs.rmSync(pidFile, { force: true });
		}
	});

	it('NEGATIVE: never removes a pid file rewritten with another pid since it was read', () => {
		fs.writeFileSync(pidFile, `${process.pid}\n`);
		try {
			assert.equal(removeIfStillNames(pidFile, process.pid + 1), false);
			assert.equal(fs.readFileSync(pidFile, 'utf8'), `${process.pid}\n`, 'stop removed a pid file naming another pid');
		} finally {
			fs.rmSync(pidFile, { force: true });
		}
	});
});
