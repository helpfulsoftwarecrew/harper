'use strict';

// sidecarKeeper.js against real processes: the parent a scope.processes sidecar runs under on Linux and darwin.
// Each test hands it a claim the way a thread does and reads back what it committed and recorded.

const assert = require('node:assert');
const { execFileSync, spawn } = require('node:child_process');
const { existsSync, lstatSync, mkdirSync, readFileSync, rmSync, utimesSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');

const { waitFor } = require('../../waitFor.js');
const { LONG_RUNNING, failOnSurvivors, reapPidDir, runningWith, stopQuietly } = require('./reap.js');
const env = require('#src/utility/environment/environmentManager');
const {
	KEEPER_SCRIPT,
	identifyKept,
	isProcessAlive,
	parentOf,
	startedAt,
} = require('#src/security/processSupervisor/processIdentity');
const { readPidLock } = require('#src/security/processSupervisor/pidFileLock');
const { keeperArgvFor } = require('#src/security/processSupervisor/sidecarLifecycle');

const DEAD_PID = 2147483646;
const BASE_MS = 50;
/** Ten first backoffs, inside which a restart that should not happen would have begun. */
const NO_RESTART_MS = 10 * BASE_MS;

function readRecord(lock) {
	try {
		return JSON.parse(readFileSync(`${lock}.exit`, 'utf-8'));
	} catch {
		return null;
	}
}

describe('sidecarKeeper.js', function () {
	failOnSurvivors();
	this.timeout(20000);
	if (process.platform === 'win32') return;

	let pidDir;
	let serial = 0;

	beforeEach(() => {
		pidDir = join(env.getHdbBasePath(), 'pids');
		reapPidDir(pidDir);
		rmSync(pidDir, { recursive: true, force: true });
		mkdirSync(pidDir, { recursive: true });
	});

	afterEach(() => {
		reapPidDir(pidDir);
		// A keeper still writing its record as the test ends can refill the directory once
		rmSync(pidDir, { recursive: true, force: true, maxRetries: 5 });
	});

	/** A claim written as the lock writes one, and a keeper launched on it as scope.processes launches one. */
	function launch(argv, { restartMax = 5, stableMs, termGraceMs, gate, token = `keeper-test-${++serial}` } = {}) {
		const lock = join(pidDir, `keeper-test-${serial}.pid`);
		writeFileSync(lock, `\n0\n${process.pid}\n${token}`);
		// A gate already standing when the keeper comes to commit, with how long ago it was written
		if (gate) {
			writeFileSync(`${lock}.claiming`, gate.content);
			const at = (Date.now() - (gate.ageMs ?? 0)) / 1000;
			utimesSync(`${lock}.claiming`, at, at);
		}
		const launcher = spawn(
			process.execPath,
			[
				KEEPER_SCRIPT,
				'--launch',
				'--lock',
				lock,
				'--token',
				token,
				'--version',
				'7',
				'--host-pid',
				String(process.pid),
				'--restarts',
				'0',
				'--restart-max',
				String(restartMax),
				'--restart-base-ms',
				String(BASE_MS),
				'--restart-cap-ms',
				'1000',
				...(stableMs ? ['--stable-ms', String(stableMs)] : []),
				...(termGraceMs ? ['--term-grace-ms', String(termGraceMs)] : []),
				'--',
				...argv,
			],
			{ stdio: 'ignore' }
		);
		return { lock, token, launcher };
	}

	async function committed(lock, token, notPid = 0) {
		return waitFor(
			() => {
				const held = readPidLock(lock);
				return held?.token === token && held.pid > 0 && held.pid !== notPid && isProcessAlive(held.pid) ? held : null;
			},
			{ timeout: 10000, message: `no keeper committed a live pid to ${lock}` }
		);
	}

	it('commits the pid it started under the claim token, with itself, its command line and the start time', async () => {
		const { lock, token, launcher } = launch([process.execPath, '-e', LONG_RUNNING]);
		const held = await committed(lock, token);
		assert.strictEqual(held.version, 7);
		assert.strictEqual(held.host, process.pid);
		assert.strictEqual(parentOf(held.pid), held.keeper, 'the process is the keeper`s own child');
		// The line a thread rebuilds for a keeper that ended before it looked, and identifies a live keeper by
		assert.deepStrictEqual(held.keeperArgv, keeperArgvFor(lock, token));
		assert.strictEqual(
			held.started,
			startedAt(held.pid),
			'the start time a thread reads is the one the keeper recorded'
		);
		// The launcher exits at once, so the keeper is init's and not this process's: no thread here reaps it
		await waitFor(() => launcher.exitCode !== null, { message: 'the launcher never exited' });
		assert.strictEqual(launcher.exitCode, 0);
		assert.notStrictEqual(
			parentOf(held.keeper),
			process.pid,
			'the keeper is still a child of the thread that launched it'
		);
		stopQuietly(held.keeper, { signal: 'SIGTERM' });
	});

	it('restarts a crash with backoff while the lock carries its token, and records the death', async () => {
		const { lock, token } = launch([process.execPath, '-e', LONG_RUNNING]);
		const first = await committed(lock, token);
		process.kill(first.pid, 'SIGKILL');
		const second = await committed(lock, token, first.pid);
		assert.strictEqual(second.keeper, first.keeper, 'one keeper across the restart');
		const record = readRecord(lock);
		assert.strictEqual(record.token, token);
		assert.strictEqual(record.pid, first.pid);
		assert.strictEqual(record.signal, 'SIGKILL');
		assert.strictEqual(record.outcome, 'restarting');
		assert.strictEqual(record.restarts, 1);
		assert.strictEqual(record.waitMs, BASE_MS);
		assert.strictEqual(isProcessAlive(first.pid), false, 'the dead process was left for someone else to reap');
		stopQuietly(second.keeper, { signal: 'SIGTERM' });
	});

	it('NEGATIVE: a SIGTERM to the process is a stop: recorded as released, the lock removed, nothing restarted', async () => {
		const { lock, token } = launch([process.execPath, '-e', LONG_RUNNING]);
		const held = await committed(lock, token);
		process.kill(held.pid, 'SIGTERM');
		await waitFor(() => !isProcessAlive(held.keeper), { message: 'the keeper outlived a deliberate stop' });
		const record = readRecord(lock);
		assert.strictEqual(record.outcome, 'released', 'a deliberate stop was not recorded as one');
		assert.strictEqual(record.signal, 'SIGTERM');
		assert.strictEqual(record.released, true, 'the keeper did not remove the lock itself');
		assert.strictEqual(existsSync(lock), false, 'the lock outlived a deliberate stop');
		await delay(NO_RESTART_MS);
		assert.strictEqual(existsSync(lock), false, 'a deliberately stopped process was started again');
	});

	it('forwards a stop signal it receives, and releases without a restart', async () => {
		const { lock, token } = launch([process.execPath, '-e', LONG_RUNNING]);
		const held = await committed(lock, token);
		process.kill(held.keeper, 'SIGTERM');
		await waitFor(() => !isProcessAlive(held.pid) && !isProcessAlive(held.keeper), {
			message: 'a SIGTERM to the keeper did not stop its process and itself',
		});
		assert.strictEqual(readRecord(lock).outcome, 'released');
		assert.strictEqual(existsSync(lock), false);
	});

	it('NEGATIVE: a lock removed before a crash ends the keeper, which starts nothing', async () => {
		const { lock, token } = launch([process.execPath, '-e', LONG_RUNNING]);
		const held = await committed(lock, token);
		// The order the shutdown stop and the reaper use: the lock goes, then the signal
		rmSync(lock);
		process.kill(held.pid, 'SIGKILL');
		await waitFor(() => !isProcessAlive(held.keeper), { message: 'the keeper outlived the loss of its lock' });
		assert.strictEqual(readRecord(lock).outcome, 'gone');
		assert.strictEqual(readRecord(lock).pid, held.pid, 'the keeper started its process again under a lost lock');
		await delay(NO_RESTART_MS);
		assert.strictEqual(existsSync(lock), false, 'a keeper whose lock was removed started its process again');
	});

	// The record beside a lock is its holder's, and a thread of that holder reads its own deaths from it
	const takersRecord = () =>
		JSON.stringify({ token: 'another-claim', keeper: 1, pid: 1, outcome: 'restarting', at: Date.now() });

	it('NEGATIVE: a lock another token took ends the keeper, which starts nothing and leaves the taker`s record', async () => {
		const marker = `taken-then-crashed-${Date.now()}`;
		const { lock, token } = launch([process.execPath, '-e', LONG_RUNNING, marker]);
		const held = await committed(lock, token);
		const other = `${held.pid}\n8\n${JSON.stringify({ token: 'another-claim', host: process.pid })}\n`;
		writeFileSync(lock, other);
		const takers = takersRecord();
		writeFileSync(`${lock}.exit`, takers);
		process.kill(held.pid, 'SIGKILL');
		await waitFor(() => !isProcessAlive(held.keeper), { message: 'the keeper outlived losing its lock' });
		assert.strictEqual(readFileSync(`${lock}.exit`, 'utf-8'), takers, 'the keeper wrote over the taker`s record');
		assert.strictEqual(readFileSync(lock, 'utf-8'), other, 'the keeper wrote over a lock that is not its own');
		await delay(NO_RESTART_MS);
		assert.deepStrictEqual(runningWith(marker), [], 'the keeper started its process again under a lost lock');
	});

	it('NEGATIVE: a keeper stopped after its lock was taken leaves the taker`s lock and record', async () => {
		const { lock, token } = launch([process.execPath, '-e', LONG_RUNNING]);
		const held = await committed(lock, token);
		const other = `${held.pid}\n8\n${JSON.stringify({ token: 'another-claim', host: process.pid })}\n`;
		writeFileSync(lock, other);
		const takers = takersRecord();
		writeFileSync(`${lock}.exit`, takers);
		process.kill(held.keeper, 'SIGTERM');
		await waitFor(() => !isProcessAlive(held.pid) && !isProcessAlive(held.keeper), {
			message: 'a SIGTERM to the keeper did not stop its process and itself',
		});
		assert.strictEqual(
			readFileSync(`${lock}.exit`, 'utf-8'),
			takers,
			'the keeper`s release wrote over the taker`s record'
		);
		assert.strictEqual(readFileSync(lock, 'utf-8'), other, 'the keeper`s release removed a lock that is not its own');
	});

	it('gives up past its cap, releasing the lock with the reason', async () => {
		const { lock, token } = launch([process.execPath, '-e', 'process.exit(3)'], { restartMax: 2 });
		await waitFor(() => readRecord(lock)?.outcome === 'gave-up', {
			timeout: 10000,
			message: 'the keeper never gave up on a process that always exits 3',
		});
		const record = readRecord(lock);
		assert.strictEqual(record.token, token);
		assert.strictEqual(record.code, 3);
		assert.strictEqual(record.restarts, 2, 'the cap counts restarts, not deaths');
		assert.strictEqual(existsSync(lock), false, 'a keeper that gave up left its lock');
	});

	it('starts a fresh count after a process that ran past --stable-ms, so its cap bounds a crash loop', async () => {
		const { lock, token } = launch([process.execPath, '-e', 'setTimeout(() => process.exit(3), 400)'], {
			restartMax: 1,
			stableMs: 200,
		});
		const pids = new Set();
		await waitFor(
			() => {
				const held = readPidLock(lock);
				if (held?.token === token && held.pid > 0) pids.add(held.pid);
				return pids.size >= 3;
			},
			{ timeout: 10000, message: 'a keeper past its cap gave up on a process that ran past --stable-ms each time' }
		);
		assert.notStrictEqual(readRecord(lock)?.outcome, 'gave-up');
		stopQuietly(readPidLock(lock)?.keeper, { signal: 'SIGTERM' });
	});

	it('NEGATIVE: a claim taken over before the commit makes it stop its process and leave the holder`s record', async () => {
		const marker = `claimed-then-taken-${Date.now()}`;
		const { lock, token, launcher } = launch([process.execPath, '-e', LONG_RUNNING, marker], {
			token: 'claimed-then-taken',
		});
		// Replaced before the keeper can commit: what a claim taken over leaves, with its holder's record beside it
		writeFileSync(lock, `\n0\n${process.pid}\nsomeone-else`);
		const holders = JSON.stringify({ token: 'someone-else', keeper: 1, pid: 1, outcome: 'restarting', at: Date.now() });
		writeFileSync(`${lock}.exit`, holders);
		await waitFor(() => launcher.exitCode !== null, { message: 'the launcher never exited' });
		await waitFor(() => runningWith(`--token ${token}`).length === 0, {
			timeout: 10000,
			message: 'the keeper of a lost claim kept running',
		});
		assert.deepStrictEqual(runningWith(marker), [], 'a process started under a lost claim kept running');
		assert.strictEqual(readFileSync(lock, 'utf-8'), `\n0\n${process.pid}\nsomeone-else`);
		assert.strictEqual(
			readFileSync(`${lock}.exit`, 'utf-8'),
			holders,
			'a losing keeper wrote over the holder`s record'
		);
	});

	// pidFileLock.ts's gate rules, which the keeper keeps its own copy of
	for (const [label, gate] of [
		['a dead holder left', () => ({ content: `${DEAD_PID}\n` })],
		['this pid left under an earlier start', () => ({ content: `${process.pid}\nThu Jan  1 00:00:00 1970` })],
		[
			'a live holder has held for a minute',
			() => ({ content: `${process.pid}\n${startedAt(process.pid)}`, ageMs: 60_000 }),
		],
	]) {
		it(`commits at once through a gate ${label}`, async () => {
			const began = Date.now();
			const { lock, token } = launch([process.execPath, '-e', LONG_RUNNING], { gate: gate() });
			const held = await committed(lock, token);
			assert.ok(Date.now() - began < 5000, `the keeper waited ${Date.now() - began}ms on a gate that was no gate`);
			stopQuietly(held.keeper, { signal: 'SIGTERM' });
		});
	}

	it('NEGATIVE: a keeper whose gate was broken while it wrote its commit writes nothing, and stops its process', async () => {
		const marker = `stalled-commit-${Date.now()}`;
		const token = `stalled-commit-${++serial}`;
		// The keeper blocks writing its temp file while it holds the gate, as a keeper stalled mid-commit would
		const temp = join(pidDir, `keeper-test-${serial}.pid.${token}.tmp`);
		execFileSync('mkfifo', [temp]);
		const { lock } = launch([process.execPath, '-e', LONG_RUNNING, marker], { token });
		const gate = `${lock}.claiming`;
		await waitFor(() => existsSync(gate) && !readFileSync(gate, 'utf-8').startsWith(`${process.pid}\n`), {
			message: 'the keeper never took its gate to commit',
		});
		// What a thread that broke the stalled keeper's gate leaves: its own gate, and the claim it has not yet decided
		const breaker = `${process.pid}\n${startedAt(process.pid) ?? ''}\nbreaker`;
		writeFileSync(gate, breaker);
		readFileSync(temp);
		try {
			await waitFor(() => runningWith(`--token ${token}`).length === 0 || lstatSync(lock).isFIFO(), {
				message: 'the keeper of a lost commit kept running',
			});
			assert.ok(!lstatSync(lock).isFIFO(), 'the stalled keeper renamed its commit over the lock');
			assert.strictEqual(readFileSync(lock, 'utf-8'), `\n0\n${process.pid}\n${token}`, 'the stalled keeper committed');
			assert.strictEqual(readFileSync(gate, 'utf-8'), breaker, 'the stalled keeper removed its breaker`s gate');
			assert.deepStrictEqual(runningWith(marker), [], 'the process of a lost commit kept running');
		} finally {
			// A FIFO renamed over the lock would hold every reader of it, the keeper and this suite's reap included
			if (lstatSync(lock, { throwIfNoEntry: false })?.isFIFO()) {
				for (const pid of [...runningWith(`--token ${token}`), ...runningWith(marker)]) stopQuietly(pid);
				rmSync(lock);
			}
			rmSync(gate, { force: true });
		}
	});

	it('NEGATIVE: a keeper whose commit was lost stops a child that ignores SIGTERM with SIGKILL after its grace', async () => {
		const marker = `lost-under-keeper-${Date.now()}`;
		const ready = join(pidDir, `${marker}.ready`);
		// Held at a live gate until the child has set its trap, so the SIGTERM that follows is one it ignores
		const { lock, token } = launch(
			['/bin/sh', '-c', 'trap "" TERM; : > "$1"; while :; do sleep 1; done', marker, ready],
			{
				gate: { content: `${process.pid}\n${startedAt(process.pid) ?? ''}\nholding` },
				termGraceMs: 200,
			}
		);
		try {
			await waitFor(() => existsSync(ready), { timeout: 10000, message: 'the child never set its trap' });
			// Taken while the keeper waits to commit, so its commit finds another token and it stops what it started
			writeFileSync(lock, `\n0\n${process.pid}\nsomeone-else`);
			rmSync(`${lock}.claiming`);
			await waitFor(() => runningWith(marker).length === 0, {
				timeout: 3000,
				message: 'a child that ignores SIGTERM outlived its keeper`s lost commit',
			});
			await waitFor(() => runningWith(`--token ${token}`).length === 0, { message: 'the keeper kept running' });
		} finally {
			for (const pid of runningWith(marker)) stopQuietly(pid);
		}
	});

	it('NEGATIVE: waits on a live holder`s young gate, and commits once it goes', async () => {
		const { lock, token } = launch([process.execPath, '-e', LONG_RUNNING], {
			gate: { content: `${process.pid}\n${startedAt(process.pid)}` },
		});
		await delay(1000);
		assert.strictEqual(readPidLock(lock)?.token, token);
		assert.strictEqual(readPidLock(lock).pid, 0, 'the keeper committed through a live holder`s gate');
		rmSync(`${lock}.claiming`);
		const held = await committed(lock, token);
		stopQuietly(held.keeper, { signal: 'SIGTERM' });
	});

	it('identifies its process through an exec by the start time it recorded, and by being its parent', async () => {
		// sh execs sleep in place: the pid and its start time stay, the program changes
		const { lock, token } = launch(['/bin/sh', '-c', 'exec sleep 600']);
		const held = await committed(lock, token);
		await waitFor(() => identifyKept(held.pid, '/bin/sh', undefined, undefined) === 'differs', {
			message: 'sh never exec`d sleep, so the command still identifies it',
		});
		assert.strictEqual(identifyKept(held.pid, '/bin/sh', undefined, { started: held.started }), 'match');
		assert.strictEqual(
			identifyKept(held.pid, '/bin/sh', undefined, { keeper: held.keeper, keeperArgv: held.keeperArgv }),
			'match',
			'the keeper that is its parent did not vouch for it'
		);
		assert.strictEqual(
			identifyKept(held.pid, '/bin/sh', undefined, { started: 'Thu Jan  1 00:00:00 1970' }),
			'differs',
			'a start time that is not this process vouched for it'
		);
		// Only the keeper of this lock and this token vouches, never the keeper of another
		const otherLock = [...held.keeperArgv.slice(0, 4), join(pidDir, 'another.pid'), ...held.keeperArgv.slice(5)];
		assert.strictEqual(
			identifyKept(held.pid, '/bin/sh', undefined, { keeper: held.keeper, keeperArgv: otherLock }),
			'differs',
			'a keeper vouched for a lock it does not carry'
		);
		stopQuietly(held.keeper, { signal: 'SIGTERM' });
	});
});
