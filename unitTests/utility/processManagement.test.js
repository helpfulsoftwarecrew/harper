'use strict';

const assert = require('node:assert');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const environment = require('#src/utility/environment/environmentManager');
const hdbTerms = require('#src/utility/hdbTerms');
const { getHdbPid, isProcessRunning } = require('#js/utility/processManagement/processManagement');
const { waitFor } = require('../waitFor.js');
const { makeZombie } = require('../zombieProcess.js');

function stopQuietly(pid) {
	try {
		process.kill(pid, 'SIGKILL');
	} catch {
		// Already gone
	}
}

// Root reads the link of an execute-only binary too, so the case below skips there
function exeIsReadable(pid) {
	try {
		fs.readlinkSync(`/proc/${pid}/exe`);
		return true;
	} catch {
		return false;
	}
}

describe('process management PID file', () => {
	let originalHdbPath;
	let testHdbPath;

	before(() => {
		originalHdbPath = environment.getHdbBasePath();
		testHdbPath = fs.mkdtempSync(path.join(os.tmpdir(), 'harper-pid-test-'));
		environment.setHdbBasePath(testHdbPath);
	});

	after(() => {
		environment.setHdbBasePath(originalHdbPath);
		fs.rmSync(testHdbPath, { force: true, recursive: true });
	});

	it('treats PID 1 as stale when an init process owns it', function () {
		if (process.platform !== 'linux') this.skip();
		const pidOneName = fs.readFileSync('/proc/1/comm', 'utf8').trim();
		if (!['catatonit', 'docker-init', 'dumb-init', 'init', 's6-svscan', 'systemd', 'tini'].includes(pidOneName))
			this.skip();
		assert.equal(isProcessRunning(1), true);
		fs.writeFileSync(path.join(testHdbPath, hdbTerms.HDB_PID_FILE), '1\n');
		assert.equal(getHdbPid(), undefined);
	});

	// Set the root beside each write: a logger timer can restore the configured root while a case awaits.
	function writePidFile(pid) {
		environment.setHdbBasePath(testHdbPath);
		fs.writeFileSync(path.join(testHdbPath, hdbTerms.HDB_PID_FILE), `${pid}\n`);
	}

	it('ignores a pid file naming a live process positively identified as not a runtime', async function () {
		if (process.platform !== 'linux' && process.platform !== 'darwin') this.skip();
		const foreign = spawn('sleep', ['600'], { stdio: 'ignore' });
		try {
			await waitFor(() => isProcessRunning(foreign.pid));
			writePidFile(foreign.pid);
			assert.equal(getHdbPid(), undefined, 'a stale pid file must not block startup because a stranger holds the pid');
			assert.equal(isProcessRunning(foreign.pid), true, 'identification must never signal');
		} finally {
			stopQuietly(foreign.pid);
		}
	});

	it('still refuses when the recorded pid runs this same runtime', async function () {
		const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1 << 30)'], { stdio: 'ignore' });
		try {
			await waitFor(() => isProcessRunning(child.pid));
			writePidFile(child.pid);
			assert.equal(getHdbPid(), child.pid, 'a live node holding the pid may be an earlier Harper');
		} finally {
			stopQuietly(child.pid);
		}
	});

	// Nothing names this holder: darwin's ps is off PATH, and Linux cannot read /proc/<pid>/exe of an execute-only binary
	it('still refuses when this platform cannot identify a live holder', async function () {
		if (process.platform !== 'linux' && process.platform !== 'darwin') this.skip();
		let command = 'sleep';
		if (process.platform === 'linux') {
			command = path.join(testHdbPath, 'sleep');
			fs.copyFileSync('/bin/sleep', command);
			fs.chmodSync(command, 0o111);
		}
		const holder = spawn(command, ['600'], { stdio: 'ignore' });
		const originalPath = process.env.PATH;
		try {
			await waitFor(() => isProcessRunning(holder.pid));
			if (process.platform === 'linux' && exeIsReadable(holder.pid)) this.skip();
			writePidFile(holder.pid);
			if (process.platform === 'darwin') process.env.PATH = testHdbPath;
			assert.equal(getHdbPid(), holder.pid, 'a live holder nothing identifies may be Harper, so startup must refuse');
		} finally {
			process.env.PATH = originalPath;
			stopQuietly(holder.pid);
		}
	});

	it('treats a pid file naming a dead-but-unreaped zombie as stale', async function () {
		if (process.platform !== 'linux' && process.platform !== 'darwin') this.skip();
		const { zombiePid, release } = await makeZombie();
		try {
			writePidFile(zombiePid);
			assert.equal(getHdbPid(), undefined, 'a zombie answers kill(pid, 0) but is not a Harper still up');
		} finally {
			release();
		}
	});
});
