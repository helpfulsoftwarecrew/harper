'use strict';
// The pid-identity primitives asked directly; getHdbPid's own tests reach them only through a pid file.

const assert = require('node:assert');
const { spawn } = require('node:child_process');

const { makeZombie } = require('../zombieProcess.js');
const { waitFor } = require('../waitFor.js');

const {
	executableOf,
	isProcessAlive,
	parseProcStatState,
	pidIsHeld,
} = require('#src/utility/processManagement/processIdentity');

describe('processIdentity', () => {
	// comm is whatever name the process gave itself, spaces and parens included.
	it('reads the state after the last close paren, not the third field', () => {
		assert.equal(parseProcStatState('7 (node) S 1 7 7 0 -1 4194304'), 'S');
		assert.equal(parseProcStatState('7 (node) Z 1 7 7 0 -1 4194304'), 'Z');
		assert.equal(parseProcStatState('7 (my app) S 1 7'), 'S', 'a comm with a space must not shift the field');
		assert.equal(parseProcStatState('7 (we(ird)) Z 1 7'), 'Z', 'a comm with parens must not end the scan early');
	});

	it('NEGATIVE: a pid nothing holds is neither held nor alive, and names no executable', () => {
		// Linux caps pid_max at 2^22 and pids stay below it, darwin far lower, so nothing there can hold 2^22 + 1
		const absent = 4_194_305;
		assert.equal(pidIsHeld(absent), false);
		assert.equal(isProcessAlive(absent), false);
		assert.equal(executableOf(absent), null);
	});

	// kill(2) reads 0 and values below -1 as a process group and -1 as every process, never one pid.
	it('NEGATIVE: anything but a positive integer is refused rather than handed to kill(2)', () => {
		for (const pid of [0, -1, -7, 1.5, Number.NaN]) {
			assert.equal(pidIsHeld(pid), false, `${pid} must not be asked of kill(2)`);
		}
	});

	// Signal 0 sends nothing. pid 1 is root's on a host, so an unprivileged run gets EPERM; any other answer skips.
	it('counts a pid another user holds as held, which kill(2) answers with EPERM', function () {
		let code;
		try {
			process.kill(1, 0);
		} catch (error) {
			code = error.code;
		}
		if (code !== 'EPERM') this.skip();
		assert.equal(pidIsHeld(1), true);
	});

	// Asserted here because darwin's ps names any zombie <defunct>, so through getHdbPid the executable check alone rejects it.
	it('NEGATIVE: a dead-but-unreaped zombie is held but not alive, and names no executable', async function () {
		if (process.platform !== 'linux' && process.platform !== 'darwin') this.skip();
		const { zombiePid, release } = await makeZombie();
		try {
			assert.equal(pidIsHeld(zombiePid), true, 'kill(pid, 0) still answers for a zombie, which is the trap');
			assert.equal(isProcessAlive(zombiePid), false, 'and liveness must not');
			assert.equal(executableOf(zombiePid), null, 'nothing is running, so nothing names an executable');
		} finally {
			release();
		}
	});

	it('identifies a live process this test started as running this same runtime', async () => {
		const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1 << 30)'], { stdio: 'ignore' });
		try {
			await waitFor(() => pidIsHeld(child.pid));
			assert.equal(pidIsHeld(child.pid), true);
			assert.equal(isProcessAlive(child.pid), true);
			const executable = executableOf(child.pid);
			// null is the honest answer on a platform that cannot say; anywhere it answers, it names this node
			if (executable !== null) {
				assert.match(executable, /node/, `executableOf said ${executable}`);
			}
		} finally {
			child.kill('SIGKILL');
		}
	});
});
