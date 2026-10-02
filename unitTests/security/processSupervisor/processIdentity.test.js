'use strict';

// The three-way identity answer behind the PID lock: "not ours" and "cannot tell" are different
// facts, and where a platform can identify, only a positive full-path identification authorizes a signal.

const assert = require('node:assert');
const { spawn } = require('node:child_process');
const { mkdtempSync, rmSync, symlinkSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const { waitFor } = require('../../waitFor.js');
const { makeZombie } = require('./zombieProcess.js');
const { asAnotherUser } = require('./anotherUser.js');
const { LONG_RUNNING, failOnSurvivors, spawnForeign, spawnOwnBinary, stopQuietly } = require('./reap.js');
const {
	argumentsOf,
	executableOf,
	identifyKeeper,
	identifyKept,
	identifyProcess,
	isProcessAlive,
	parentOf,
	parseProcStatState,
	platformCanIdentifyProcesses,
	startedAt,
	_setPsTimeoutForTests,
} = require('#src/security/processSupervisor/processIdentity');

// A pid high enough that nothing holds it, for the "recorded process is gone" cases
const DEAD_PID = 2147483646;
const CHILD = join(__dirname, 'fixtures', 'supervisedProcess.mjs');

describe('processIdentity', () => {
	failOnSurvivors();

	describe('isProcessAlive', () => {
		it('refuses the process-group selectors kill(2) accepts', () => {
			assert.strictEqual(isProcessAlive(0), false, '0 is the caller process group');
			assert.strictEqual(isProcessAlive(-1), false, 'a negative selects group -n');
			assert.strictEqual(isProcessAlive(1.5), false, 'a non-integer is not a pid');
		});

		it('distinguishes a live pid from a dead one', () => {
			assert.strictEqual(isProcessAlive(process.pid), true);
			assert.strictEqual(isProcessAlive(DEAD_PID), false);
		});

		it('treats a dead-but-unreaped zombie as not alive', async function () {
			if (process.platform !== 'linux' && process.platform !== 'darwin') this.skip();
			const { zombiePid, release } = await makeZombie();
			try {
				// The blind spot this closes: kill(pid, 0) still answers for a zombie
				assert.doesNotThrow(() => process.kill(zombiePid, 0));
				assert.strictEqual(isProcessAlive(zombiePid), false);
				assert.strictEqual(executableOf(zombiePid), null, 'a zombie runs no executable to report');
				assert.strictEqual(
					identifyProcess(zombiePid, process.execPath),
					'differs',
					'a zombie holds no identity a lock may adopt, so its lock is reclaimable'
				);
			} finally {
				release();
			}
		});
	});

	describe('parseProcStatState', () => {
		it('reads the state from after the LAST paren, surviving comms with spaces and parens', () => {
			assert.strictEqual(parseProcStatState('987 (tricky ) (comm) Z 1 987 987 0 -1 4227136 120 0 0 0'), 'Z');
			assert.strictEqual(parseProcStatState('42 (node) R 1 42 42 0 -1 4194560 21011 0 0 0'), 'R');
		});

		it('answers null rather than guessing when the content does not parse', () => {
			assert.strictEqual(parseProcStatState('no stat fields here'), null);
			assert.strictEqual(parseProcStatState(''), null);
			assert.strictEqual(parseProcStatState('123 (comm)'), null);
		});
	});

	describe('identifyProcess', () => {
		it('separates ours, not-ours and cannot-tell', () => {
			assert.strictEqual(identifyProcess(DEAD_PID, process.execPath), 'differs', 'a dead pid runs nothing of ours');
			assert.strictEqual(
				identifyProcess(process.pid, '/nonexistent/agent'),
				'unknown',
				'an unresolvable command says nothing about the process'
			);
			assert.strictEqual(identifyProcess(process.pid, ''), 'unknown');
		});

		it('positively identifies a child spawned from an absolute path', async function () {
			if (!platformCanIdentifyProcesses()) this.skip();
			const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1 << 30)'], { stdio: 'ignore' });
			try {
				await waitFor(() => isProcessAlive(child.pid));
				assert.strictEqual(identifyProcess(child.pid, process.execPath), 'match');
			} finally {
				stopQuietly(child.pid);
			}
		});

		it('never answers match for a live process running another binary', async function () {
			if (process.platform === 'win32') this.skip();
			const foreign = spawnForeign();
			try {
				await waitFor(() => isProcessAlive(foreign.pid));
				assert.strictEqual(identifyProcess(foreign.pid, process.execPath), 'differs');
				assert.strictEqual(isProcessAlive(foreign.pid), true, 'identification must never signal');
			} finally {
				stopQuietly(foreign.pid);
			}
		});
	});

	describe('executableOf', () => {
		it('answers null rather than guessing for a pid nothing holds', () => {
			assert.strictEqual(executableOf(DEAD_PID), null);
		});
	});

	// An interpreter is the same binary for every script it is given, so the executable alone answers
	// for `node` and not for the program. What tells one node from another is the argument vector.
	describe('identifyProcess with a script', () => {
		let dir;
		let sideA;
		let sideB;

		before(() => {
			dir = mkdtempSync(join(tmpdir(), 'process-identity-script-'));
			sideA = join(dir, 'sideA.js');
			sideB = join(dir, 'sideB.js');
			writeFileSync(sideA, LONG_RUNNING);
			writeFileSync(sideB, LONG_RUNNING);
		});

		after(() => rmSync(dir, { recursive: true, force: true }));

		it('REGRESSION: two unrelated node scripts do not share one identity', async function () {
			if (!platformCanIdentifyProcesses()) this.skip();
			const a = spawn(process.execPath, [sideA], { stdio: 'ignore' });
			const b = spawn(process.execPath, [sideB], { stdio: 'ignore' });
			try {
				await waitFor(() => isProcessAlive(a.pid) && isProcessAlive(b.pid));
				// Without the script, the executable behind both is this node binary, so either pid answers 'match'
				assert.strictEqual(
					identifyProcess(b.pid, process.execPath),
					'match',
					'the executable alone cannot tell two node scripts apart, which is the defect'
				);
				assert.strictEqual(identifyProcess(b.pid, process.execPath, sideA), 'differs', 'sideB is not sideA');
				assert.strictEqual(identifyProcess(a.pid, process.execPath, sideB), 'differs', 'nor sideA sideB');
				assert.strictEqual(identifyProcess(a.pid, process.execPath, sideA), 'match');
				assert.strictEqual(identifyProcess(b.pid, process.execPath, sideB), 'match');
				assert.strictEqual(isProcessAlive(a.pid) && isProcessAlive(b.pid), true, 'identification must never signal');
			} finally {
				stopQuietly(a.pid);
				stopQuietly(b.pid);
			}
		});

		it('a native binary with no script argument answers exactly as it did', async function () {
			if (process.platform === 'win32') this.skip();
			const child = spawn('/bin/sleep', ['600'], { stdio: 'ignore' });
			try {
				await waitFor(() => isProcessAlive(child.pid));
				assert.strictEqual(identifyProcess(child.pid, '/bin/sleep'), 'match');
				assert.strictEqual(identifyProcess(child.pid, process.execPath), 'differs');
			} finally {
				stopQuietly(child.pid);
			}
		});

		it('an argv it cannot compare stays unknown rather than matching on the interpreter', async function () {
			if (!platformCanIdentifyProcesses()) this.skip();
			const child = spawn(process.execPath, [sideA], { stdio: 'ignore' });
			// The same script named the way another process would carry it: relative to a cwd that is not ours
			const relative = spawn(process.execPath, ['sideA.js'], { cwd: dir, stdio: 'ignore' });
			try {
				await waitFor(() => isProcessAlive(child.pid) && isProcessAlive(relative.pid));
				assert.strictEqual(
					identifyProcess(child.pid, process.execPath, join(dir, 'absent.js')),
					'unknown',
					'a script that is not on disk says nothing about the process'
				);
				assert.strictEqual(
					identifyProcess(relative.pid, process.execPath, sideA),
					'unknown',
					'an argument that agrees only by name forbids the signal and the reclaim alike'
				);
				assert.strictEqual(argumentsOf(DEAD_PID), null, 'a pid nothing holds surrenders no argv');
				// argv is process-writable, so a matching script cannot upgrade an unresolved executable
				assert.strictEqual(identifyProcess(child.pid, 'node', sideA), 'unknown');
			} finally {
				stopQuietly(child.pid);
				stopQuietly(relative.pid);
			}
		});
	});

	// A sidecar Harper spawned runs as Harper's user, so on Linux a process this user may not signal or read is not one
	describe("another user's process on Linux", () => {
		let stranger;

		before(async () => {
			// This node running the fixture script, which both halves would otherwise identify
			stranger = spawn(process.execPath, [CHILD], { stdio: 'ignore' });
			await waitFor(() => isProcessAlive(stranger.pid));
		});

		after(() => stopQuietly(stranger.pid));

		it('answers not ours for a pid that refuses kill(pid, 0) with EPERM, with a script or without', async () => {
			const { result, signals } = await asAnotherUser({ pid: stranger.pid, kill: 'EPERM' }, () => [
				isProcessAlive(stranger.pid),
				identifyProcess(stranger.pid, process.execPath),
				identifyProcess(stranger.pid, process.execPath, CHILD),
			]);
			assert.deepStrictEqual(result, [true, 'differs', 'differs'], 'EPERM means held, by another user');
			assert.deepStrictEqual(signals, [], 'identification must never signal');
		});

		it('answers not ours for a pid whose executable link refuses the read with EACCES', async () => {
			const { result } = await asAnotherUser({ pid: stranger.pid, readlink: 'EACCES' }, () => [
				identifyProcess(stranger.pid, process.execPath),
				identifyProcess(stranger.pid, process.execPath, CHILD),
			]);
			assert.deepStrictEqual(result, ['differs', 'differs']);
		});

		it('NEGATIVE: an executable link that is absent rather than refused stays cannot tell', async () => {
			// A kernel thread's, as a Harper running as root reads it: ENOENT says nothing about whose it is
			const { result } = await asAnotherUser({ pid: stranger.pid, readlink: 'ENOENT' }, () =>
				identifyProcess(stranger.pid, process.execPath)
			);
			assert.strictEqual(result, 'unknown');
		});
	});

	describe('start time and parent', () => {
		it('reads one start time for a process however often it is asked, and another for a different one', async function () {
			if (!platformCanIdentifyProcesses()) this.skip();
			const child = spawnOwnBinary();
			try {
				await waitFor(() => isProcessAlive(child.pid));
				const started = startedAt(child.pid);
				assert.ok(started, 'no start time was read for a live child');
				assert.strictEqual(startedAt(child.pid), started, 'the start time moved between two reads');
				assert.strictEqual(parentOf(child.pid), process.pid);
				assert.strictEqual(startedAt(DEAD_PID), null, 'a pid nothing holds has no start time');
			} finally {
				stopQuietly(child.pid);
			}
		});

		it('NEGATIVE: pid 1 and a pid nothing holds vouch for nothing as a keeper', () => {
			assert.strictEqual(identifyKeeper(1, ['/sbin/init']), 'differs');
			assert.strictEqual(identifyKeeper(DEAD_PID, [process.execPath]), 'differs');
		});

		it('ships a two-second `ps` timeout', () => {
			assert.strictEqual(_setPsTimeoutForTests(), 2000);
		});

		it('NEGATIVE: a recorded start time that is not the pid`s says another process, however well its binary matches', async function () {
			if (!platformCanIdentifyProcesses()) this.skip();
			const child = spawnOwnBinary();
			try {
				await waitFor(() => isProcessAlive(child.pid) && startedAt(child.pid) !== null);
				assert.strictEqual(
					identifyProcess(child.pid, process.execPath),
					'match',
					'the binary must match for this to bind'
				);
				const other = { started: 'Thu Jan  1 00:00:00 1970' };
				assert.strictEqual(identifyKept(child.pid, process.execPath, undefined, other), 'differs');
				assert.strictEqual(
					identifyKept(child.pid, process.execPath, undefined, { started: startedAt(child.pid) }),
					'match'
				);
			} finally {
				stopQuietly(child.pid);
			}
		});
	});

	describe('a command line under a path outside ASCII, whatever the caller`s locale', () => {
		/** Runs `read` with this process's locale replaced by `locale`, as a service started by launchd has none. */
		function inLocale(locale, read) {
			const isLocale = (key) => key === 'LANG' || key.startsWith('LC_');
			const saved = Object.fromEntries(Object.entries(process.env).filter(([key]) => isLocale(key)));
			for (const key of Object.keys(saved)) delete process.env[key];
			Object.assign(process.env, locale);
			try {
				return read();
			} finally {
				for (const key of Object.keys(process.env).filter(isLocale)) delete process.env[key];
				Object.assign(process.env, saved);
			}
		}

		for (const [label, locale] of [
			['with no locale', {}],
			['in the C locale', { LC_ALL: 'C' }],
		]) {
			it(`identifies the process and the keeper that runs it ${label}`, async function () {
				if (!platformCanIdentifyProcesses()) this.skip();
				// darwin's ps prints a command line's bytes outside ASCII escaped in the C locale, a launchd service's default
				const dir = mkdtempSync(join(tmpdir(), 'harper-café-'));
				const node = join(dir, 'node');
				symlinkSync(process.execPath, node);
				// A keeper's command line names its lock; a plain argument, since node reads one led by `--` as its own
				const argv = [node, '-e', LONG_RUNNING, join(dir, 'pids', 'x.pid')];
				const child = spawn(argv[0], argv.slice(1), { stdio: 'ignore' });
				try {
					await waitFor(() => isProcessAlive(child.pid));
					const [asProcess, asKeeper] = inLocale(locale, () => [
						identifyProcess(child.pid, node),
						identifyKeeper(child.pid, argv),
					]);
					assert.strictEqual(asProcess, 'match', 'a process under a path outside ASCII read as another program');
					assert.strictEqual(asKeeper, 'match', 'a keeper under a path outside ASCII read as gone');
				} finally {
					stopQuietly(child.pid);
					rmSync(dir, { recursive: true, force: true });
				}
			});
		}
	});

	describe('platformCanIdentifyProcesses', () => {
		it('claims identification only where the platform exposes it', () => {
			const expected = process.platform === 'linux' || process.platform === 'darwin';
			assert.strictEqual(platformCanIdentifyProcesses(), expected);
		});
	});
});
