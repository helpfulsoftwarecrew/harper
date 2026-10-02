'use strict';

// The descriptor registry and the graceful-shutdown stop it feeds, which acts only while hdb.pid names
// this process, so a handover never stops the children its replacement adopts.

const assert = require('node:assert');
const { existsSync, mkdirSync, rmSync, unlinkSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');

const { setTimeout: delay } = require('node:timers/promises');
const { waitFor } = require('../../waitFor.js');
const { asAnotherUser } = require('./anotherUser.js');
const {
	failOnSurvivors,
	reapPidDir,
	spawnExecdShell,
	spawnForeign,
	spawnOwnBinary,
	stopQuietly,
} = require('./reap.js');
const env = require('#src/utility/environment/environmentManager');
const {
	identifyProcess,
	isProcessAlive,
	platformCanIdentifyProcesses,
	startedAt,
} = require('#src/security/processSupervisor/processIdentity');
const {
	_setExitGateWaitForTests,
	readSidecarTargets,
	sidecarDescriptorPath,
	stopSidecarsAtExit,
	writeSidecarTarget,
} = require('#src/security/processSupervisor/sidecarRegistry');

describe('sidecarRegistry', function () {
	failOnSurvivors();
	this.timeout(20000);
	let pidDir;
	let hdbPidPath;

	beforeEach(() => {
		pidDir = join(env.getHdbBasePath(), 'pids');
		hdbPidPath = join(env.getHdbBasePath(), 'hdb.pid');
		// The locks and descriptors are the only record of what this test started, so reap before removing them
		reapPidDir(pidDir);
		rmSync(pidDir, { recursive: true, force: true });
		mkdirSync(pidDir, { recursive: true });
	});

	afterEach(() => {
		// The locks and descriptors are the only record of what this test started, so reap before removing them
		reapPidDir(pidDir);
		rmSync(pidDir, { recursive: true, force: true });
		try {
			unlinkSync(hdbPidPath);
		} catch {
			// Not every test writes one
		}
	});

	function record(name, pid, command) {
		const target = { name, pidFile: join(pidDir, `${name}.pid`), pid, command };
		writeSidecarTarget(pidDir, target);
		writeFileSync(target.pidFile, `${pid}\n1`);
		return target;
	}

	/** What a node leaves behind a sidecar it started: hdb.pid naming it, and a live child recorded under `name`. */
	async function recordedChild(name, command = process.execPath) {
		writeFileSync(hdbPidPath, String(process.pid));
		const child = spawnOwnBinary();
		await waitFor(() => isProcessAlive(child.pid));
		return { child, target: record(name, child.pid, command) };
	}

	describe('the descriptor files', () => {
		it('round-trips a target and skips what it cannot read', () => {
			const target = { name: 'agent', pidFile: join(pidDir, 'agent.pid'), pid: 4242, command: '/opt/agent' };
			writeSidecarTarget(pidDir, target);
			writeFileSync(join(pidDir, 'broken.sidecar.json'), 'not json');
			writeFileSync(join(pidDir, 'wrong-shape.sidecar.json'), JSON.stringify({ pid: 'not a number' }));
			// A descriptor that cannot be read names nothing to act on, so only the good one survives
			assert.deepStrictEqual(readSidecarTargets(pidDir), [target]);
		});

		it('an absent directory reads as no targets rather than a throw', () => {
			assert.deepStrictEqual(readSidecarTargets(join(pidDir, 'nowhere')), []);
		});
	});

	describe('stopSidecarsAtExit', () => {
		it('stops an identified sidecar, removing its lock but leaving the descriptor for the reaper', async function () {
			if (process.platform === 'win32') this.skip();
			const { child, target } = await recordedChild('agent');
			try {
				stopSidecarsAtExit();

				await waitFor(() => !isProcessAlive(child.pid), { timeout: 5000 });
				assert.strictEqual(existsSync(target.pidFile), false, 'the lock must go before the signal');
				// The descriptor stays so the reaper can escalate a SIGTERM-ignoring child, then remove it
				assert.strictEqual(existsSync(sidecarDescriptorPath(pidDir, 'agent')), true);
			} finally {
				stopQuietly(child.pid);
			}
		});

		it('stops a sidecar that exec`d into another program by the start time its keeper recorded', async function () {
			if (process.platform === 'win32') this.skip();
			writeFileSync(hdbPidPath, String(process.pid));
			const child = spawnExecdShell();
			try {
				await waitFor(() => identifyProcess(child.pid, '/bin/sh') === 'differs', { message: 'sh never exec`d' });
				const target = record('wrapped', child.pid, '/bin/sh');
				const kept = { token: 'kept-token', host: process.pid, started: startedAt(child.pid) };
				writeFileSync(target.pidFile, `${child.pid}\n1\n${JSON.stringify(kept)}\n`);

				stopSidecarsAtExit();

				await waitFor(() => !isProcessAlive(child.pid), {
					timeout: 5000,
					message: 'a kept sidecar that exec`d was left running at shutdown',
				});
				assert.strictEqual(existsSync(target.pidFile), false, 'the lock must go before the signal');
			} finally {
				stopQuietly(child.pid);
			}
		});

		it('NEGATIVE: never signals a live process the descriptor cannot identify as ours', async function () {
			if (process.platform === 'win32') this.skip();
			writeFileSync(hdbPidPath, String(process.pid));
			const foreign = spawnForeign();
			try {
				await waitFor(() => isProcessAlive(foreign.pid));
				// The descriptor claims this pid runs node; the pid demonstrably runs sleep (pid reuse)
				const target = record('agent', foreign.pid, process.execPath);

				stopSidecarsAtExit();

				assert.strictEqual(isProcessAlive(foreign.pid), true, 'an unidentified process was signalled');
				assert.strictEqual(existsSync(target.pidFile), false, 'the stale lock is ours to remove');
				assert.strictEqual(existsSync(sidecarDescriptorPath(pidDir, 'agent')), false);
			} finally {
				stopQuietly(foreign.pid);
			}
		});

		// Discarding the descriptor here would leave a running sidecar that nothing can find again
		it('CRITICAL: falls back to the pid it recorded when the lock names a live stranger', async function () {
			if (process.platform === 'win32') this.skip();
			writeFileSync(hdbPidPath, String(process.pid));
			const child = spawnOwnBinary();
			const stranger = spawnForeign();
			try {
				await waitFor(() => isProcessAlive(child.pid) && isProcessAlive(stranger.pid));
				const target = record('agent', child.pid, process.execPath);
				// The lock names a live sleep this test owns, which is not node and must never be signalled
				writeFileSync(target.pidFile, `${stranger.pid}\n1`);

				stopSidecarsAtExit();

				await waitFor(() => !isProcessAlive(child.pid), {
					timeout: 5000,
					message: 'the recorded pid was never reached, so the sidecar was stranded',
				});
				assert.strictEqual(isProcessAlive(stranger.pid), true, 'the stranger the lock names was signalled');
				assert.strictEqual(existsSync(target.pidFile), false, 'the overwritten lock is ours to remove');
			} finally {
				stopQuietly(child.pid);
				stopQuietly(stranger.pid);
			}
		});

		it('waits a second at most on a gate this process holds, since exit cannot wait out the lock`s deadline', async function () {
			if (process.platform === 'win32') this.skip();
			const { child, target } = await recordedChild('agent');
			try {
				// What a thread ended inside the gate leaves: this pid and this start, which no liveness read clears
				writeFileSync(`${target.pidFile}.claiming`, `${process.pid}\n${startedAt(process.pid) ?? ''}`);
				const startedStop = Date.now();

				_setExitGateWaitForTests(200);
				try {
					stopSidecarsAtExit();
				} finally {
					assert.strictEqual(_setExitGateWaitForTests(), 1000, 'the shipped wait on a held gate');
				}

				assert.ok(Date.now() - startedStop < 5000, `the exit-time stop waited ${Date.now() - startedStop}ms on a gate`);
				await waitFor(() => !isProcessAlive(child.pid), { timeout: 5000 });
			} finally {
				stopQuietly(child.pid);
			}
		});

		it('NEGATIVE: never signals a pid running the same binary with another start time than the descriptor records', async function () {
			if (!platformCanIdentifyProcesses()) this.skip();
			writeFileSync(hdbPidPath, String(process.pid));
			const stranger = spawnOwnBinary();
			try {
				await waitFor(() => isProcessAlive(stranger.pid) && startedAt(stranger.pid) !== null);
				const target = { ...record('agent', stranger.pid, process.execPath), started: 'Thu Jan  1 00:00:00 1970' };
				writeSidecarTarget(pidDir, target);
				rmSync(target.pidFile);

				stopSidecarsAtExit();

				assert.strictEqual(isProcessAlive(stranger.pid), true, 'a reused pid was signalled on its binary alone');
				assert.strictEqual(existsSync(sidecarDescriptorPath(pidDir, 'agent')), false, 'the stale descriptor stayed');
			} finally {
				stopQuietly(stranger.pid);
			}
		});

		// The fallback must not become a second way to signal a stranger. When the lock's pid and the
		// descriptor's both run another program, the files are simply stale.
		it('NEGATIVE: signals nothing when the recorded pid is a stranger too', async function () {
			if (process.platform === 'win32') this.skip();
			writeFileSync(hdbPidPath, String(process.pid));
			const foreign = spawnForeign();
			const stranger = spawnForeign();
			try {
				await waitFor(() => isProcessAlive(foreign.pid) && isProcessAlive(stranger.pid));
				// The descriptor claims a node sidecar and names a live `sleep`; the lock names a second one.
				const target = record('agent', foreign.pid, process.execPath);
				writeFileSync(target.pidFile, `${stranger.pid}\n1`);

				stopSidecarsAtExit();

				await delay(300);
				assert.strictEqual(isProcessAlive(foreign.pid), true, 'the recorded stranger was signalled');
				assert.strictEqual(isProcessAlive(stranger.pid), true, 'the stranger the lock names was signalled');
				assert.strictEqual(existsSync(target.pidFile), false, 'the stale lock is ours to remove');
				assert.strictEqual(existsSync(sidecarDescriptorPath(pidDir, 'agent')), false);
			} finally {
				stopQuietly(foreign.pid);
				stopQuietly(stranger.pid);
			}
		});

		// A sidecar Harper spawned runs as Harper's user, so on Linux a lock naming a pid this user may not
		// signal names someone else's process, and the recorded pid is the way back even with no script
		it("on Linux, falls back to the pid it recorded when the lock names another user's process", async function () {
			if (process.platform === 'win32') this.skip();
			writeFileSync(hdbPidPath, String(process.pid));
			const child = spawnOwnBinary();
			const stranger = spawnOwnBinary();
			try {
				await waitFor(() => isProcessAlive(child.pid) && isProcessAlive(stranger.pid));
				const target = record('agent', child.pid, process.execPath);
				writeFileSync(target.pidFile, `${stranger.pid}\n1`);

				const { signals } = await asAnotherUser(
					{ pid: stranger.pid, kill: 'EPERM', exe: { [child.pid]: process.execPath } },
					() => stopSidecarsAtExit()
				);

				await waitFor(() => !isProcessAlive(child.pid), {
					timeout: 5000,
					message: 'the recorded pid was never reached, so the sidecar was stranded',
				});
				assert.deepStrictEqual(signals, [], "another user's process was signalled");
				assert.strictEqual(isProcessAlive(stranger.pid), true);
				assert.strictEqual(existsSync(target.pidFile), false, 'the lock naming someone else is ours to remove');
			} finally {
				stopQuietly(child.pid);
				stopQuietly(stranger.pid);
			}
		});

		it('NEGATIVE: leaves everything alone when identification cannot be established', async () => {
			// An unresolvable command answers "cannot tell" everywhere, so the stop signals nothing and keeps both files
			const { child: holder, target } = await recordedChild('agent', '/nonexistent/agent');
			try {
				stopSidecarsAtExit();

				assert.strictEqual(isProcessAlive(holder.pid), true);
				assert.strictEqual(existsSync(target.pidFile), true);
				assert.strictEqual(existsSync(sidecarDescriptorPath(pidDir, 'agent')), true);
			} finally {
				stopQuietly(holder.pid);
			}
		});

		it('cleans up after a sidecar that is already gone', () => {
			writeFileSync(hdbPidPath, String(process.pid));
			const target = record('agent', 2147483646, '/opt/agent');
			stopSidecarsAtExit();
			assert.strictEqual(existsSync(target.pidFile), false);
			assert.strictEqual(existsSync(sidecarDescriptorPath(pidDir, 'agent')), false);
		});

		it('CRITICAL: does nothing when hdb.pid names another process, which is what a restart handover looks like', async () => {
			const child = spawnOwnBinary();
			try {
				await waitFor(() => isProcessAlive(child.pid));
				const target = record('agent', child.pid, process.execPath);

				// A replacement already owns hdb.pid; stopping here would strand the adoption it depends on
				writeFileSync(hdbPidPath, '2147483646');
				stopSidecarsAtExit();
				assert.strictEqual(isProcessAlive(child.pid), true, 'a handover stopped the children its replacement adopts');
				assert.strictEqual(existsSync(target.pidFile), true);

				// And restart removes hdb.pid entirely before the old main exits
				unlinkSync(hdbPidPath);
				stopSidecarsAtExit();
				assert.strictEqual(isProcessAlive(child.pid), true);
			} finally {
				stopQuietly(child.pid);
			}
		});
	});
});
