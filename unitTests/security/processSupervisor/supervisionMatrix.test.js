'use strict';

// The supervision matrix: who is watching a process (the thread that started it, or a thread that
// joined one already running) against how that process dies. One table below, one runner under it.

const assert = require('node:assert');
const { spawn } = require('node:child_process');
const { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');

const { waitFor } = require('../../waitFor.js');
const { TEST_TIMING, collectingLogger } = require('./helpers.js');
const { LONG_RUNNING, failOnSurvivors, reapPidDir, stopQuietly, track } = require('./reap.js');
const { processState } = require('./zombieProcess.js');
const env = require('#src/utility/environment/environmentManager');
const { isProcessAlive } = require('#src/security/processSupervisor/processIdentity');
const { scopedImport } = require('#src/security/jsLoader');
const { child_processConstrained, spawnKept } = require('#src/security/processSupervisor/constrainedChildProcess');
const { _setPollIntervalForTests } = require('#src/security/processSupervisor/adoptionWrapper');
const { _setIdentifyDeadlineForTests, readPidLock } = require('#src/security/processSupervisor/pidFileLock');
const {
	REAPER_NAME,
	SidecarProcesses,
	_setTimingForTests,
	fingerprintVersion,
} = require('#src/security/processSupervisor/sidecarLifecycle');

const CHILD = join(__dirname, 'fixtures', 'supervisedProcess.mjs');
const COMPONENT = join(__dirname, 'fixtures', 'supervisedComponent.mjs');
/** A clean exit on demand: the death mode an owner spares and a joiner, holding no exit status, cannot. */
const EXIT_ZERO_ON_SIGNAL = `process.on('SIGUSR2', () => process.exit(0)); ${LONG_RUNNING}`;
/** More than one watcher of a single ownerless death, which is what the claim has to reduce to one. */
const JOINER_THREADS = 3;

// The shipped timing scaled down: a joiner's wrapper polls every POLL_MS and darwin reads the process state
// every tenth poll, so a corpse takes up to ten polls to notice and a live process that long to prove quiet
const POLL_MS = 25;
const DARWIN_STATE_READ_EVERY = 10;
const IDENTIFY_DEADLINE_MS = 25;
// A deadline ends as soon as its condition holds, so its slack for a loaded runner costs a passing run nothing
const DEATH_DEADLINE_MS = 5000;
const ZOMBIE_DEADLINE_MS = 5000;
const JOINED_QUIET_MS = process.platform === 'darwin' ? (DARWIN_STATE_READ_EVERY + 2) * POLL_MS : 3 * POLL_MS;
// A component's own spawn holds a real child and runs no poll, so its negative case has no cadence to cross
const OWNED_QUIET_MS = 10 * POLL_MS;
const RESPAWN_DEADLINE_MS = 5000;
// Ten first backoffs, inside which a restart that should not happen would have begun
const NO_RESTART_WINDOW_MS = 10 * TEST_TIMING.respawnBaseMs;
// backoffMs(0) + rejoinGraceMs in sidecarLifecycle.ts: how long a thread that stood down looks for
// the replacement before it stops answering with the pid it watched die
const REJOIN_WINDOW_MS = TEST_TIMING.respawnBaseMs + TEST_TIMING.rejoinGraceMs;
const REJOIN_DEADLINE_MS = REJOIN_WINDOW_MS + 5000;

/** Every line a supervisor emits when it believes something died, whatever level it grades at. */
const DEATH_LINE = /has died|was terminated by|exited with code|exited cleanly|restarting the/;
const NO_LINES = Object.freeze({ info: [], warn: [], error: [] });

/** A real process this suite owns, alive before it is handed to a cell and signalled at teardown. */
async function holder(ctx, command, args) {
	const child = spawn(command, args, { stdio: 'ignore' });
	ctx.keep(() => stopQuietly(child.pid, { signal: 'SIGKILL' }));
	await waitFor(() => isProcessAlive(child.pid), { message: `the holder ${command} never came up` });
	return child.pid;
}

/**
 * A process whose parent never wait()s it: sh forks it, prints its pid, then execs in place, so the
 * exec keeps sh's pid and a killed target stays an unreaped corpse the way it does under a bare init.
 */
async function foster(ctx, command, args) {
	const quoted = [command, ...args].map((part) => `'${String(part).replaceAll("'", `'\\''`)}'`).join(' ');
	const parent = spawn('/bin/sh', ['-c', `${quoted} & echo $!; exec sleep 3600`], {
		stdio: ['ignore', 'pipe', 'ignore'],
	});
	ctx.keep(() => stopQuietly(parent.pid, { signal: 'SIGKILL' }));
	let output = '';
	parent.stdout.on('data', (chunk) => (output += chunk));
	const printed = await waitFor(() => output.trim(), { message: 'sh never printed the fostered pid' });
	const pid = Number.parseInt(String(printed), 10);
	// Stopped before its parent, or a cell that fails before the kill leaves it running under pid 1
	ctx.keep(() => stopQuietly(pid, { signal: 'SIGKILL' }));
	track(pid);
	await waitFor(() => isProcessAlive(pid), { message: `the fostered pid ${pid} never came up` });
	return pid;
}

/** Kills the target and waits until the platform reports the corpse, so the cell polls against a real zombie. */
async function killIntoZombie(id, pid) {
	process.kill(pid, 'SIGKILL');
	await waitFor(() => processState(pid) === 'Z', { message: `${id}: the target never turned zombie` });
	assert.doesNotThrow(() => process.kill(pid, 0), `${id}: the blind spot is kill(pid, 0) answering for a corpse`);
}

function descriptorFor(name, args, extra) {
	return { name, command: 'node', args, fingerprint: [name], reaper: false, ...extra };
}

/** Starts a sidecar this thread owns; `die` makes the first incarnation exit once with that code. */
async function ownedSidecar(ctx, name, { die, exitHint, verify } = {}) {
	const logger = collectingLogger();
	const args = [CHILD];
	// The marker leaves the restarted incarnation running forever, so one death does not become a loop
	if (die !== undefined) args.push(join(ctx.workDir, `${name}.marker`), String(die));
	const state = await supervisor(ctx, logger).start(descriptorFor(name, args, { exitHint, verify }));
	assert.strictEqual(state.adopted, false, `${name} must have started the process, not joined one`);
	ctx.keep(() => stopQuietly(state.pid, { signal: 'SIGTERM' }));
	if (die === undefined) {
		assert.strictEqual(state.started, true, `${name} did not start`);
		return { observed: state, lines: logger.lines, firstPid: state.pid };
	}
	// A child that dies at once can be answered before start() returns, and a clean exit clears `started`
	const startLine = logger.lines.info.map((line) => /started the .*\(pid (\d+)\)/.exec(line)).find(Boolean);
	assert.ok(startLine, `${name} did not start`);
	return { observed: state, lines: logger.lines, firstPid: Number(startLine[1]) };
}

/** One thread joining a process it did not start; the lock that hands it the wrapper is already in place. */
async function joinOnce(ctx, name, target, extra = {}) {
	const logger = collectingLogger();
	const state = await supervisor(ctx, logger).start(descriptorFor(name, [CHILD], extra));
	assert.strictEqual(state.adopted, true, `${name}: the lock must hand this thread the wrapper`);
	assert.strictEqual(state.pid, target, `${name}: the joiner must join the running pid`);
	// Read at teardown rather than copied: a thread that claims a death moves state.pid to its own child
	ctx.keep(() => stopQuietly(state.pid, { signal: 'SIGTERM' }));
	return { observed: state, lines: logger.lines, target };
}

/** Joins a process no thread on this node owns, which is what an ops-API restart leaves every thread. */
async function joinedSidecar(ctx, name, target, threads = 1) {
	mkdirSync(ctx.pidDir, { recursive: true });
	writeFileSync(ctx.lockPath(name), `${target}\n${fingerprintVersion(name)}`);
	const joiners = [];
	for (let index = 0; index < threads; index++) joiners.push(await joinOnce(ctx, name, target));
	return { ...joiners[0], joiners };
}

/**
 * The thread that started a process and a joiner handed the wrapper, both watching it. The joiner polls at
 * the shipped interval: a poll landing between the death and the owner's unlink is the claim's one race.
 */
async function ownedAndJoined(ctx, name, extra = {}) {
	const owner = await ownedSidecar(ctx, name, extra);
	_setPollIntervalForTests();
	try {
		return { ...(await joinOnce(ctx, name, owner.observed.pid, extra)), owner };
	} finally {
		_setPollIntervalForTests(POLL_MS);
	}
}

/** The pid a lock names, or null when it is absent; the one thing a joiner reads to decide about a death. */
function lockedPid(ctx, name) {
	try {
		return Number.parseInt(readFileSync(ctx.lockPath(name), 'utf-8').split('\n')[0], 10);
	} catch {
		return null;
	}
}

/** Refuses once the cell has ended, so a restart or relaunch timer that outlives it starts nothing. */
function whileOpen(ctx, start) {
	return (...args) => {
		if (!ctx.open) throw new Error('the cell that owned this supervisor has ended');
		return start(...args);
	};
}

/** A supervisor on the real constrained spawn, fork and keeper, all closed with its cell. */
function supervisor(ctx, logger, keep = whileOpen(ctx, spawnKept)) {
	return new SidecarProcesses(
		logger,
		whileOpen(ctx, child_processConstrained.spawn),
		whileOpen(ctx, child_processConstrained.fork),
		keep
	);
}

/**
 * The keeper-backed spawn with the reaper pointed at a child this suite can kill on demand. It still goes through
 * the real keeper and the real singleton lock; the shipped reaper's own behaviour has its own suite.
 */
function reaperKeep(ctx, die) {
	const args = die === undefined ? [] : [join(ctx.workDir, `reaper-${die}.marker`), String(die)];
	// The lock the reaper was started for goes with it, since that is what identifies a reaper as this node's
	return whileOpen(ctx, (command, spawnArgs, options) =>
		options.name === REAPER_NAME
			? spawnKept(command, [CHILD, ...args, ...(options.identity ?? [])], { ...options, script: CHILD })
			: spawnKept(command, spawnArgs, options)
	);
}

/** Starts a sidecar with the reaper enabled, so #ensureReaper launches or joins behind it. */
async function withReaper(ctx, name, die) {
	const logger = collectingLogger();
	const processes = supervisor(ctx, logger, reaperKeep(ctx, die));
	const state = await processes.start(descriptorFor(name, [CHILD], { reaper: true }));
	assert.strictEqual(state.started, true, `${name} did not start, so no reaper was reached`);
	ctx.keep(() => stopQuietly(state.pid, { signal: 'SIGTERM' }));
	ctx.keep(() => stopQuietly(processes.reaper?.pid, { signal: 'SIGTERM' }));
	return { processes, logger, state };
}

/** Whether the supervisor logged a death, at any level, for the subject it watches. */
function deathLogged(subject) {
	return Object.values(subject.lines).some((lines) => lines.some((line) => DEATH_LINE.test(line)));
}

function assertLine(id, lines, level, pattern) {
	assert.ok(
		lines[level].some((line) => pattern.test(line)),
		`${id}: no ${level} line matching ${pattern}; saw ${JSON.stringify(lines[level])}`
	);
}

function assertNoLine(id, lines, level, pattern) {
	const found = lines[level].find((line) => pattern.test(line));
	assert.strictEqual(found, undefined, `${id}: an unexpected ${level} line matching ${pattern}: ${found}`);
}

/** Holds a live subject under observation, failing the instant a death is reported rather than at the end. */
async function assertQuiet(id, subject, windowMs) {
	const deadline = Date.now() + windowMs;
	do {
		assert.ok(!subject.observed.exited, `${id}: a death was reported for a process that is still running`);
		await delay(50);
	} while (Date.now() < deadline);
	assert.strictEqual(
		isProcessAlive(subject.target ?? subject.observed.pid),
		true,
		`${id}: the subject died on its own`
	);
}

/** The ownerless verdict: the thread that claimed the lock restarted once and started the new process itself. */
async function assertClaimantRestarted(id, subject, ctx, name) {
	await waitFor(() => subject.observed.restarts === 1, {
		timeout: RESPAWN_DEADLINE_MS,
		message: `${id}: the thread that claimed the lock never restarted the process`,
	});
	await waitFor(() => lockedPid(ctx, name) === subject.observed.pid, {
		timeout: RESPAWN_DEADLINE_MS,
		message: `${id}: the lock never came to name the restarted process, so the next death is unowned again`,
	});
	assert.notStrictEqual(subject.observed.pid, subject.target, `${id}: a restart must be a new process`);
	assert.strictEqual(
		subject.observed.adopted,
		false,
		`${id}: the claimant must have started the process, not joined a second wrapper`
	);
	assert.strictEqual(isProcessAlive(subject.observed.pid), true, `${id}: the lock names a process that is not running`);
}

/** A thread that stood down must end up holding a wrapper on the live replacement, not the pid it watched die. */
async function assertRejoined(id, joiner, deadPid, replacementPid) {
	await waitFor(() => joiner.observed.pid === replacementPid, {
		timeout: REJOIN_DEADLINE_MS,
		message: `${id}: a thread that stood down still reports dead pid ${deadPid} as the running sidecar, not ${replacementPid}`,
	});
	assert.strictEqual(
		joiner.observed.adopted,
		true,
		`${id}: a rejoin must adopt the replacement, not start a second one`
	);
	assert.strictEqual(joiner.observed.started, true, `${id}: a thread that rejoined reports nothing running`);
	assert.notStrictEqual(
		joiner.observed.exited,
		true,
		`${id}: a rejoined thread still reports dead pid ${deadPid} as exited`
	);
	assert.strictEqual(joiner.observed.restarts, 0, `${id}: a rejoin must spend none of the restart attempts`);
	assert.strictEqual(isProcessAlive(replacementPid), true, `${id}: the pid a rejoined thread reports is not running`);
}

/** The other end of the rejoin: nothing replaced the process, so the thread stops describing the corpse. */
async function assertReportsNothingRunning(id, subject, deadPid) {
	await waitFor(() => subject.observed.started === false, {
		timeout: REJOIN_DEADLINE_MS,
		message: `${id}: no replacement came, and this thread still reports dead pid ${deadPid} as started`,
	});
	assert.strictEqual(subject.observed.pid, undefined, `${id}: a thread supervising nothing kept a pid`);
	assert.strictEqual(subject.observed.verified, undefined, `${id}: a thread supervising nothing kept verify's verdict`);
	assertLine(
		id,
		subject.lines,
		'warn',
		new RegExp(`nothing replaced the .* in the ${REJOIN_WINDOW_MS}ms after its death`)
	);
}

/**
 * The reaper came back on the object the consumer already holds, since a status endpoint rereads that one.
 * `deadPid` is optional because one cell's reaper dies on its own during arrange, too fast to sample.
 */
async function assertReaperReplaced(id, subject, ctx, deadPid = undefined) {
	// A keeper's restart keeps `started` through the death, so the replacement is a live pid with the death cleared
	const replaced = () =>
		subject.observed.started === true &&
		subject.observed.exited !== true &&
		subject.observed.pid !== deadPid &&
		isProcessAlive(subject.observed.pid);
	await waitFor(replaced, {
		timeout: RESPAWN_DEADLINE_MS,
		message: `${id}: nothing replaced the reaper this node lost, on the state the consumer holds`,
	});
	const replacement = subject.processes.reaper;
	assert.strictEqual(replacement, subject.observed, `${id}: the relaunch swapped the object a reader holds`);
	assert.strictEqual(replacement.exited, undefined, `${id}: the replacement still carries the last death`);
	assert.strictEqual(replacement.error, undefined, `${id}: and the reason for it`);
	assert.strictEqual(isProcessAlive(replacement.pid), true, `${id}: the replacement is not running`);
	if (deadPid !== undefined)
		assert.notStrictEqual(replacement.pid, deadPid, `${id}: the replacement carries the pid that died`);
	// The singleton lock has to name the replacement, or the next thread joins a corpse
	assert.strictEqual(lockedPid(ctx, REAPER_NAME), replacement.pid, `${id}: the lock names something else`);
}

/** Proves the absence of a restart the way the presence of one is proven: over a window, not at an instant. */
async function assertNoRestart(id, subject) {
	const deadline = Date.now() + NO_RESTART_WINDOW_MS;
	do {
		assert.strictEqual(subject.observed.restarts, 0, `${id}: this thread restarted a process it must not`);
		await delay(50);
	} while (Date.now() < deadline);
}

/**
 * The matrix. A row is one permutation: arrange a supervised process, deliver a death (or none), then
 * assert what the supervisor learned. `unreachable` states why a cell cannot be built instead of faking it.
 */
const MATRIX = [
	// scope.processes, owner: this thread won the PID lock and started the process under a keeper, whose record says how it ended
	{
		id: 'h-sidecar-owner-exit-zero',
		expect: 'an owner reports a clean exit and restarts nothing',
		arrange: (ctx) => ownedSidecar(ctx, 'matrix-owner-exit-zero', { die: 0 }),
		observe: 'death',
		lines: { info: /exited cleanly/ },
		silent: { warn: DEATH_LINE, error: DEATH_LINE },
		then: async (subject) => {
			// The exit status is what tells a reader a stop from a crash
			assert.strictEqual(subject.observed.code, 0, 'the code a reader needs to tell a stop from a crash');
			assert.strictEqual(subject.observed.signal, undefined, 'nothing signalled this one');
			await assertNoRestart('h-sidecar-owner-exit-zero', subject);
		},
	},
	{
		id: 'h-sidecar-owner-exit-nonzero',
		expect: 'an owner reports a non-zero exit with the descriptor hint and restarts the child itself',
		arrange: (ctx) => ownedSidecar(ctx, 'matrix-owner-exit-nonzero', { die: 3, exitHint: 'the port may be held' }),
		observe: 'death',
		lines: { error: /exited with code 3;.*the port may be held/ },
		then: async (subject) => {
			await waitFor(() => subject.observed.restarts === 1, {
				timeout: RESPAWN_DEADLINE_MS,
				message: 'h-sidecar-owner-exit-nonzero: the owner never restarted the child it started',
			});
			assert.notStrictEqual(subject.observed.pid, subject.firstPid, 'a restart must be a new process');
			await waitFor(() => isProcessAlive(subject.observed.pid), {
				message: 'h-sidecar-owner-exit-nonzero: the restarted child never came up',
			});
		},
	},
	{
		id: 'h-sidecar-owner-sigterm',
		expect: 'an owner warns on SIGTERM and does not fight whoever sent it',
		arrange: (ctx) => ownedSidecar(ctx, 'matrix-owner-sigterm'),
		act: (subject) => process.kill(subject.observed.pid, 'SIGTERM'),
		observe: 'death',
		lines: { warn: /was terminated by SIGTERM/ },
		silent: { warn: /restarting the/, error: DEATH_LINE },
		then: async (subject) => {
			assert.strictEqual(subject.observed.signal, 'SIGTERM', 'the signal that ended it');
			assert.strictEqual(subject.observed.code, undefined, 'a signalled process has no exit code');
			// Nothing will run under this name again, so the state names no pid rather than the one that was stopped
			assert.strictEqual(subject.observed.started, false, 'a stopped process is still reported started');
			assert.strictEqual(subject.observed.pid, undefined, 'and the pid that was stopped is still published');
			await assertNoRestart('h-sidecar-owner-sigterm', subject);
		},
	},
	{
		id: 'h-sidecar-owner-sigkill',
		expect: 'an owner grades SIGKILL as a crash and restarts with backoff',
		arrange: (ctx) => ownedSidecar(ctx, 'matrix-owner-sigkill'),
		act: (subject) => process.kill(subject.observed.pid, 'SIGKILL'),
		observe: 'death',
		// The backoff itself, not just that one happened: the first wait and the cap the attempts count against
		lines: {
			error: /was terminated by SIGKILL; that is a crash or an OOM kill/,
			warn: new RegExp(`restarting the .* in ${TEST_TIMING.respawnBaseMs}ms after signal SIGKILL \\(attempt 1 of 5\\)`),
		},
		then: async (subject) => {
			assert.strictEqual(subject.observed.signal, 'SIGKILL', 'the signal that ended the first incarnation');
			await waitFor(() => subject.observed.restarts === 1, {
				timeout: RESPAWN_DEADLINE_MS,
				message: 'h-sidecar-owner-sigkill: the owner never restarted the crashed child',
			});
			assert.notStrictEqual(subject.observed.pid, subject.firstPid, 'a restart must be a new process');
			// Cleared with `exited` and `error`, or they describe a dead process beside a live pid
			assert.strictEqual(subject.observed.signal, undefined, 'the dead incarnation`s signal outlived it');
			assert.strictEqual(subject.observed.code, undefined, 'the dead incarnation`s code outlived it');
		},
	},
	{
		id: 'h-sidecar-owner-zombie',
		expect: 'the thread that started a process never sees it die into a zombie',
		unreachable:
			"the process is its keeper's child, and the keeper wait()s every death whether or not that thread still runs; libuv reaps a direct child only while the thread that spawned it lives, and every cell here keeps its thread alive, so the case is bound with the thread ended in unitTests/security/processSupervisor/sidecarOwnerGone.test.js",
	},
	{
		id: 'h-sidecar-owner-alive',
		expect: 'an owner reports no death across the whole state-read cadence for a process still running',
		arrange: (ctx) => ownedSidecar(ctx, 'matrix-owner-alive'),
		observe: 'no-death',
		silent: { warn: DEATH_LINE, error: DEATH_LINE },
		then: (subject, ctx) =>
			assert.strictEqual(existsSync(ctx.lockPath('matrix-owner-alive')), true, 'the lock must outlive the start'),
	},

	// scope.processes, joiner of a process under a keeper: every thread reads the keeper's record of a death,
	// and a keeper restarts its own process, so a joiner claims nothing while it lives
	{
		id: 'h-sidecar-joined-kept-death',
		expect: 'a joiner of a process under a keeper leaves the restart to the keeper and joins the one it restarts',
		posixOnly: true,
		arrange: (ctx) => ownedAndJoined(ctx, 'matrix-joined-owned'),
		act: (subject) => process.kill(subject.target, 'SIGKILL'),
		observe: 'death',
		lines: {
			error: /was terminated by SIGKILL; that is a crash or an OOM kill/,
			warn: new RegExp(`its keeper is restarting the .* in ${TEST_TIMING.respawnBaseMs}ms after signal SIGKILL`),
		},
		silent: { warn: /claimed its PID lock/ },
		then: async (subject, ctx) => {
			const id = 'h-sidecar-joined-kept-death';
			await waitFor(() => subject.observed.pid !== subject.target && isProcessAlive(subject.observed.pid), {
				timeout: RESPAWN_DEADLINE_MS,
				message: `${id}: a joiner still reports dead pid ${subject.target}, not the keeper's replacement`,
			});
			await waitFor(() => subject.owner.observed.pid === subject.observed.pid, {
				timeout: RESPAWN_DEADLINE_MS,
				message: `${id}: the owner and the joiner report different processes, so one of them started a second`,
			});
			assert.strictEqual(lockedPid(ctx, 'matrix-joined-owned'), subject.observed.pid, `${id}: the lock names another`);
			assert.strictEqual(subject.observed.adopted, true, `${id}: the joiner started a process of its own`);
			assert.strictEqual(subject.observed.exited, undefined, `${id}: the joiner still reports the death`);
			assert.strictEqual(subject.observed.restarts, 1, `${id}: the keeper's one restart is not what the state reports`);
		},
	},
	{
		id: 'h-sidecar-joined-kept-deliberate-stop',
		expect: 'a stop under a keeper leaves the owner and a joiner reporting nothing running, and neither restarts it',
		posixOnly: true,
		arrange: (ctx) => ownedAndJoined(ctx, 'matrix-joined-kept-stopped', { verify: async () => ({ ok: true }) }),
		act: (subject) => process.kill(subject.target, 'SIGTERM'),
		observe: 'death',
		lines: { warn: /was terminated by SIGTERM/ },
		silent: { warn: /claimed its PID lock|restarting the/ },
		then: async (subject, ctx) => {
			const id = 'h-sidecar-joined-kept-deliberate-stop';
			for (const [who, observed] of [
				['joiner', subject.observed],
				['owner', subject.owner.observed],
			]) {
				await waitFor(() => observed.started === false, {
					timeout: DEATH_DEADLINE_MS,
					message: `${id}: the ${who} still reports stopped pid ${subject.target} as started`,
				});
				assert.strictEqual(observed.pid, undefined, `${id}: the ${who} still publishes the stopped pid`);
				assert.strictEqual(observed.verified, undefined, `${id}: the ${who} still vouches for the stopped pid`);
				assert.strictEqual(observed.verifiedPid, undefined, `${id}: the ${who} still names the pid it proved`);
			}
			await assertNoRestart(id, subject);
			assert.strictEqual(existsSync(ctx.lockPath('matrix-joined-kept-stopped')), false, `${id}: a lock was written`);
		},
	},
	{
		id: 'h-sidecar-joined-kept-zombie',
		expect: 'a joiner sees a process under a keeper die into a corpse',
		unreachable:
			"the keeper is the process's parent and wait()s each death as it happens, so no state Z is observable while it lives; a joiner polling a corpse no keeper reaps is h-sidecar-joined-ownerless-zombie, and the keeper's reaping with the starting thread ended is bound in unitTests/security/processSupervisor/sidecarOwnerGone.test.js",
	},

	// scope.processes, joiner of a process with no keeper: the lock is the whole discriminator. Still naming the pid it
	// watched die means nobody else has this death; a final stop unlinks first and a version replacement relocks in the gate.
	{
		id: 'h-sidecar-joined-ownerless-death-released',
		expect: 'a joiner whose process died with no owner on this node claims its lock and is the one restarting it',
		posixOnly: true,
		arrange: async (ctx) =>
			joinedSidecar(ctx, 'matrix-joined-released', await holder(ctx, process.execPath, ['-e', LONG_RUNNING])),
		act: (subject) => process.kill(subject.target, 'SIGKILL'),
		observe: 'death',
		lines: { warn: /has died with no thread on this node owning it; this thread claimed its PID lock/ },
		then: (subject, ctx) =>
			assertClaimantRestarted('h-sidecar-joined-ownerless-death-released', subject, ctx, 'matrix-joined-released'),
	},
	{
		id: 'h-sidecar-joined-ownerless-exit-zero',
		expect: 'an ownerless clean exit is restarted as well, because a joiner is handed no exit status to spare it',
		posixOnly: true,
		arrange: async (ctx) =>
			joinedSidecar(ctx, 'matrix-joined-exit-zero', await holder(ctx, process.execPath, ['-e', EXIT_ZERO_ON_SIGNAL])),
		act: (subject) => process.kill(subject.target, 'SIGUSR2'),
		observe: 'death',
		lines: { warn: /has died with no thread on this node owning it; this thread claimed its PID lock/ },
		// The asymmetry this cell exists for: an owner grades the same death cleanly and restarts nothing
		silent: { info: /exited cleanly/ },
		then: (subject, ctx) =>
			assertClaimantRestarted('h-sidecar-joined-ownerless-exit-zero', subject, ctx, 'matrix-joined-exit-zero'),
	},
	{
		id: 'h-sidecar-joined-ownerless-zombie',
		expect: 'a joiner claims a death into a corpse nothing reaps, which kill(pid, 0) cannot see',
		posixOnly: true,
		deadlineMs: ZOMBIE_DEADLINE_MS,
		arrange: async (ctx) =>
			joinedSidecar(ctx, 'matrix-joined-zombie', await foster(ctx, process.execPath, ['-e', LONG_RUNNING])),
		act: (subject) => killIntoZombie('h-sidecar-joined-ownerless-zombie', subject.target),
		observe: 'death',
		lines: { warn: /has died with no thread on this node owning it; this thread claimed its PID lock/ },
		then: (subject, ctx) =>
			assertClaimantRestarted('h-sidecar-joined-ownerless-zombie', subject, ctx, 'matrix-joined-zombie'),
	},
	{
		id: 'h-sidecar-joined-ownerless-one-claimant',
		expect: 'many threads watching one ownerless death produce one restart, so the capped backoff is not multiplied',
		posixOnly: true,
		arrange: async (ctx) =>
			joinedSidecar(
				ctx,
				'matrix-joined-claimants',
				await holder(ctx, process.execPath, ['-e', LONG_RUNNING]),
				JOINER_THREADS
			),
		act: (subject) => process.kill(subject.target, 'SIGKILL'),
		observe: 'death',
		then: async (subject, ctx) => {
			const id = 'h-sidecar-joined-ownerless-one-claimant';
			const said = (joiner, text) => joiner.lines.warn.some((line) => line.includes(text));
			await waitFor(() => subject.joiners.every((joiner) => said(joiner, 'has died')), {
				timeout: DEATH_DEADLINE_MS,
				message: `${id}: a thread never noticed the death of the process it joined`,
			});
			const claimants = subject.joiners.filter((joiner) => said(joiner, 'claimed its PID lock'));
			assert.strictEqual(
				claimants.length,
				1,
				`${id}: ${claimants.length} of ${JOINER_THREADS} threads claimed one death; more than one multiplies the capped backoff by the thread count`
			);
			await assertClaimantRestarted(id, claimants[0], ctx, 'matrix-joined-claimants');
			for (const loser of subject.joiners.filter((joiner) => !claimants.includes(joiner))) {
				assert.ok(said(loser, 'no longer names it'), `${id}: a thread that lost the claim did not report the death`);
				assert.strictEqual(loser.observed.restarts, 0, `${id}: a thread that lost the claim restarted anyway`);
			}
		},
	},
	{
		id: 'h-sidecar-joined-ownerless-stood-down-rejoins',
		expect: 'the threads that stood down from an ownerless death end up reporting the live replacement, not the corpse',
		posixOnly: true,
		arrange: async (ctx) =>
			joinedSidecar(
				ctx,
				'matrix-joined-rejoin',
				await holder(ctx, process.execPath, ['-e', LONG_RUNNING]),
				JOINER_THREADS
			),
		act: (subject) => process.kill(subject.target, 'SIGKILL'),
		observe: 'death',
		then: async (subject, ctx) => {
			const id = 'h-sidecar-joined-ownerless-stood-down-rejoins';
			const said = (joiner, text) => joiner.lines.warn.some((line) => line.includes(text));
			await waitFor(() => subject.joiners.every((joiner) => said(joiner, 'has died')), {
				timeout: DEATH_DEADLINE_MS,
				message: `${id}: a thread never noticed the death of the process it joined`,
			});
			const claimant = subject.joiners.find((joiner) => said(joiner, 'claimed its PID lock'));
			assert.ok(claimant, `${id}: no thread claimed the death, so there is no replacement for the others to rejoin`);
			await assertClaimantRestarted(id, claimant, ctx, 'matrix-joined-rejoin');
			// Each thread that stood down must report the replacement, not the pid that died
			for (const stoodDown of subject.joiners.filter((joiner) => joiner !== claimant)) {
				await assertRejoined(id, stoodDown, subject.target, claimant.observed.pid);
				assert.ok(
					!said(stoodDown, 'restarting the'),
					`${id}: a thread that rejoined the replacement restarted something as well`
				);
			}
		},
	},
	{
		id: 'h-sidecar-joined-ownerless-late-watcher',
		expect: 'a watcher polling after a faster thread has already relocked declines the claim and joins that process',
		posixOnly: true,
		arrange: async (ctx) => {
			const target = await holder(ctx, process.execPath, ['-e', LONG_RUNNING]);
			const subject = await joinedSidecar(ctx, 'matrix-joined-late', target);
			subject.replacement = await holder(ctx, process.execPath, ['-e', LONG_RUNNING]);
			return subject;
		},
		// The one case an absent lock does not cover: darwin reads the process state every tenth poll, so a
		// watcher can first look after the claim it lost has respawned and written a lock naming a live pid
		act: (subject, ctx) => {
			process.kill(subject.target, 'SIGKILL');
			const version = fingerprintVersion('matrix-joined-late');
			writeFileSync(ctx.lockPath('matrix-joined-late'), `${subject.replacement}\n${version}`);
		},
		observe: 'death',
		lines: { warn: /has died and its PID lock no longer names it.* will join whatever replaces it/ },
		silent: { warn: /claimed its PID lock|restarting the/ },
		then: async (subject, ctx) => {
			const id = 'h-sidecar-joined-ownerless-late-watcher';
			await assertNoRestart(id, subject);
			assert.strictEqual(
				lockedPid(ctx, 'matrix-joined-late'),
				subject.replacement,
				`${id}: a live replacement had its lock taken away by a late watcher`
			);
			// Declining is half of it; the watcher must then join the pid the lock names, not report the one that died
			await assertRejoined(id, subject, subject.target, subject.replacement);
			assert.strictEqual(
				lockedPid(ctx, 'matrix-joined-late'),
				subject.replacement,
				`${id}: a rejoin must read the lock, never rewrite it`
			);
		},
	},
	{
		id: 'h-sidecar-joined-deliberate-stop',
		expect: 'a joiner restarts nothing when the lock went before the death, and ends reporting nothing running',
		posixOnly: true,
		arrange: async (ctx) =>
			joinedSidecar(ctx, 'matrix-joined-stopped', await holder(ctx, process.execPath, ['-e', LONG_RUNNING])),
		// The order the shutdown stop and the reaper use: the lock goes first, leaving nothing to claim
		act: (subject, ctx) => {
			rmSync(ctx.lockPath('matrix-joined-stopped'), { force: true });
			process.kill(subject.target, 'SIGTERM');
		},
		observe: 'death',
		lines: { warn: /has died and its PID lock no longer names it.* will join whatever replaces it/ },
		silent: { warn: /claimed its PID lock|restarting the/ },
		then: async (subject, ctx) => {
			const id = 'h-sidecar-joined-deliberate-stop';
			await assertNoRestart(id, subject);
			assert.strictEqual(
				existsSync(ctx.lockPath('matrix-joined-stopped')),
				false,
				`${id}: a thread that must not restart wrote a lock anyway`
			);
			// An absent lock is nothing to rejoin, so the wait runs out and the stopped pid is not reported as running
			await assertReportsNothingRunning(id, subject, subject.target);
			assert.strictEqual(
				existsSync(ctx.lockPath('matrix-joined-stopped')),
				false,
				`${id}: a thread that found no replacement spawned one anyway`
			);
		},
	},
	{
		id: 'h-sidecar-joined-alive',
		expect: 'a joiner reports no death across the whole state-read cadence for a process still running',
		posixOnly: true,
		arrange: async (ctx) =>
			joinedSidecar(ctx, 'matrix-joined-alive', await holder(ctx, process.execPath, ['-e', LONG_RUNNING])),
		observe: 'no-death',
		silent: { warn: DEATH_LINE, error: DEATH_LINE },
	},

	// The non-sidecar path: a component that imports child_process itself and gets the constrained spawn
	{
		id: 'h-raw-owner-death',
		expect: 'a component that started a process sees the real cause and its lock is removed',
		arrange: async (ctx) => {
			const owner = ctx.component.runProcess('matrix-raw-owner', 'node', ['-e', LONG_RUNNING]);
			ctx.keep(() => stopQuietly(owner.pid, { signal: 'SIGKILL' }));
			assert.strictEqual(owner.adopted, false, 'the first call must win the lock and hold a real child');
			assert.strictEqual(existsSync(ctx.lockPath('matrix-raw-owner')), true, 'a winning spawn writes the lock');
			return { observed: owner, lines: NO_LINES, target: owner.pid };
		},
		act: (subject) => process.kill(subject.target, 'SIGKILL'),
		observe: 'death',
		then: async (subject, ctx) => {
			assert.strictEqual(subject.observed.signal, 'SIGKILL', 'only an owner can tell the death causes apart');
			await waitFor(() => !existsSync(ctx.lockPath('matrix-raw-owner')), {
				message: 'h-raw-owner-death: the lock outlived its process, so the next thread would join a dead pid',
			});
		},
	},
	{
		id: 'h-raw-owner-alive',
		expect: 'a live component process keeps its lock, and a second call joins it rather than starting another',
		arrange: async (ctx) => {
			const owner = ctx.component.runProcess('matrix-raw-owner-alive', 'node', ['-e', LONG_RUNNING]);
			ctx.keep(() => stopQuietly(owner.pid, { signal: 'SIGKILL' }));
			return { observed: owner, lines: NO_LINES, target: owner.pid };
		},
		observe: 'no-death',
		quietMs: OWNED_QUIET_MS,
		then: (subject, ctx) => {
			assert.strictEqual(existsSync(ctx.lockPath('matrix-raw-owner-alive')), true, 'the lock names the live pid');
			const joiner = ctx.component.runProcess('matrix-raw-owner-alive', 'node', ['-e', LONG_RUNNING]);
			assert.strictEqual(joiner.adopted, true, 'the second call must be handed the wrapper');
			assert.strictEqual(joiner.pid, subject.target, 'and must join, not start a second process');
		},
	},
	{
		id: 'h-raw-joined-death-released',
		expect: 'a component that joined a running process still learns of its death after unref, and cannot tell why',
		arrange: async (ctx) => {
			const owner = ctx.component.runProcess('matrix-raw-joined', 'node', ['-e', LONG_RUNNING]);
			ctx.keep(() => stopQuietly(owner.pid, { signal: 'SIGKILL' }));
			assert.strictEqual(owner.adopted, false, 'the first call must win the lock');
			const joiner = ctx.component.runProcess('matrix-raw-joined', 'node', ['-e', LONG_RUNNING]);
			assert.strictEqual(joiner.adopted, true, 'the second call must be handed the wrapper');
			assert.strictEqual(joiner.pid, owner.pid, 'and must join the running process');
			return { observed: joiner, lines: NO_LINES, target: owner.pid };
		},
		act: (subject) => process.kill(subject.target, 'SIGKILL'),
		observe: 'death',
		then: async (subject) => {
			assert.strictEqual(subject.observed.code, null, 'a joiner is handed no exit code');
			assert.strictEqual(subject.observed.signal, null, 'nor a signal, so it cannot tell a crash from a stop');
			await delay(2 * POLL_MS);
			assert.strictEqual(subject.observed.exits, 1, 'h-raw-joined-death-released: one death was reported twice');
		},
	},
	{
		id: 'h-raw-joined-zombie',
		expect: 'a component that joined a process reports it dying into a corpse nothing reaps',
		posixOnly: true,
		deadlineMs: ZOMBIE_DEADLINE_MS,
		arrange: async (ctx) => {
			const target = await foster(ctx, process.execPath, ['-e', LONG_RUNNING]);
			mkdirSync(ctx.pidDir, { recursive: true });
			// A bare command name identifies as "cannot tell", so the lock joins this pid rather than reclaiming it
			writeFileSync(ctx.lockPath('matrix-raw-zombie'), `${target}\n0`);
			const joiner = ctx.component.runProcess('matrix-raw-zombie', 'node', ['-e', LONG_RUNNING]);
			assert.strictEqual(joiner.adopted, true, 'the lock must hand back the wrapper');
			assert.strictEqual(joiner.pid, target, 'and must join the fostered pid');
			return { observed: joiner, lines: NO_LINES, target };
		},
		act: (subject) => killIntoZombie('h-raw-joined-zombie', subject.target),
		observe: 'death',
		then: (subject) => assert.strictEqual(subject.observed.exits, 1, 'a corpse must be reported once'),
	},
	{
		id: 'h-raw-joined-alive',
		expect: 'a component that joined a live process reports nothing across the whole state-read cadence',
		arrange: async (ctx) => {
			const owner = ctx.component.runProcess('matrix-raw-joined-alive', 'node', ['-e', LONG_RUNNING]);
			ctx.keep(() => stopQuietly(owner.pid, { signal: 'SIGKILL' }));
			const joiner = ctx.component.runProcess('matrix-raw-joined-alive', 'node', ['-e', LONG_RUNNING]);
			assert.strictEqual(joiner.adopted, true, 'the second call must be handed the wrapper');
			return { observed: joiner, lines: NO_LINES, target: owner.pid };
		},
		observe: 'no-death',
		then: (subject) => assert.strictEqual(subject.observed.exits, 0, 'no death may be reported for a live process'),
	},

	// #ensureReaper: the process whose death means every sidecar outlives this node, under a keeper as a sidecar is
	{
		id: 'h-ensure-reaper-owner-exit-nonzero',
		expect: 'a reaper that exits non-zero is restarted by its keeper, and the thread joins the one it restarts',
		arrange: async (ctx) => {
			const { processes, logger } = await withReaper(ctx, 'matrix-reaper-owner-nonzero', 3);
			assert.strictEqual(processes.reaper?.adopted, false, 'the first start launches the reaper');
			return { observed: processes.reaper, lines: logger.lines, processes };
		},
		observe: 'death',
		lines: { error: /the sidecar reaper exited with code 3; its keeper restarts it/ },
		then: (subject, ctx) => assertReaperReplaced('h-ensure-reaper-owner-exit-nonzero', subject, ctx),
	},
	// A SIGKILL is a loss, not a graceful stop, so a killed reaper is reported and replaced
	{
		id: 'h-ensure-reaper-owner-sigkill',
		expect: 'a SIGKILLed reaper is reported as a crash and restarted by its keeper',
		arrange: async (ctx) => {
			const { processes, logger } = await withReaper(ctx, 'matrix-reaper-owner-sigkill');
			assert.strictEqual(processes.reaper?.adopted, false, 'the first start launches the reaper');
			return { observed: processes.reaper, lines: logger.lines, processes };
		},
		act: (subject) => {
			subject.killed = subject.observed.pid;
			process.kill(subject.killed, 'SIGKILL');
		},
		observe: 'death',
		lines: { error: /the sidecar reaper was terminated by SIGKILL; that is a crash or an OOM kill/ },
		then: (subject, ctx) => assertReaperReplaced('h-ensure-reaper-owner-sigkill', subject, ctx, subject.killed),
	},
	{
		id: 'h-ensure-reaper-owner-sigterm',
		expect: 'a reaper stopped deliberately is reported gone and not replaced',
		arrange: async (ctx) => {
			const { processes, logger } = await withReaper(ctx, 'matrix-reaper-owner-sigterm');
			assert.strictEqual(processes.reaper?.adopted, false, 'the first start launches the reaper');
			return { observed: processes.reaper, lines: logger.lines, processes };
		},
		act: (subject) => process.kill(subject.observed.pid, 'SIGTERM'),
		observe: 'death',
		// A deliberate stop is not a fault, so nothing here may read as one
		lines: { warn: /the sidecar reaper was terminated by SIGTERM/ },
		silent: { warn: /restarting the/, error: DEATH_LINE },
		then: async (subject) => {
			assert.strictEqual(subject.observed.started, false, 'a reaper that has died is not started');
			assert.strictEqual(subject.observed.error, undefined, 'a deliberate stop is not an error');
			// The state is reused across a relaunch, so `started` returning to true is what a replacement looks like
			await delay(NO_RESTART_WINDOW_MS);
			assert.strictEqual(
				subject.observed.started,
				false,
				'h-ensure-reaper-owner-sigterm: a deliberately stopped reaper was replaced anyway'
			);
			assert.strictEqual(subject.observed.pid, undefined, 'and it published a pid for one');
		},
	},
	{
		id: 'h-ensure-reaper-owner-zombie',
		expect: 'the thread that launched the reaper never sees it die into a zombie',
		unreachable:
			"the reaper is its keeper's child, and the keeper wait()s every death whether or not the thread that launched it still runs; the case with that thread ended is bound in unitTests/security/processSupervisor/sidecarOwnerGone.test.js",
	},
	{
		id: 'h-ensure-reaper-owner-alive',
		expect: 'a launched reaper holds its singleton lock and the next thread joins it',
		arrange: async (ctx) => {
			const { processes, logger } = await withReaper(ctx, 'matrix-reaper-owner-alive');
			assert.strictEqual(processes.reaper?.started, true, 'the reaper must launch');
			return { observed: processes.reaper, lines: logger.lines, target: processes.reaper.pid };
		},
		observe: 'no-death',
		quietMs: OWNED_QUIET_MS,
		silent: { warn: /sidecar reaper/, error: /sidecar reaper/ },
		then: async (subject, ctx) => {
			assert.strictEqual(existsSync(ctx.lockPath(REAPER_NAME)), true, 'the lock that makes the reaper a singleton');
			const { processes } = await withReaper(ctx, 'matrix-reaper-owner-alive');
			assert.strictEqual(processes.reaper?.adopted, true, 'a second thread must join the reaper');
			assert.strictEqual(processes.reaper.pid, subject.target, 'and must not launch a second one');
		},
	},
	{
		id: 'h-ensure-reaper-joined-kept-death',
		expect: 'a thread that joined the reaper leaves its restart to the keeper and joins the one it restarts',
		posixOnly: true,
		arrange: async (ctx) => {
			const first = await withReaper(ctx, 'matrix-reaper-joined');
			assert.strictEqual(first.processes.reaper?.adopted, false, 'the first start launches the reaper');
			const second = await withReaper(ctx, 'matrix-reaper-joined');
			assert.strictEqual(second.processes.reaper?.adopted, true, 'the second thread must join it');
			assert.strictEqual(second.processes.reaper.pid, first.processes.reaper.pid, 'and share its pid');
			return {
				observed: second.processes.reaper,
				lines: second.logger.lines,
				target: first.processes.reaper.pid,
				processes: second.processes,
			};
		},
		act: (subject) => process.kill(subject.target, 'SIGKILL'),
		observe: 'death',
		lines: { warn: /its keeper is restarting the sidecar reaper/ },
		silent: { warn: /claimed its PID lock/ },
		then: async (subject, ctx) => {
			await assertReaperReplaced('h-ensure-reaper-joined-kept-death', subject, ctx, subject.target);
			assert.strictEqual(subject.observed.adopted, true, 'the joiner launched a reaper of its own');
		},
	},
	{
		id: 'h-ensure-reaper-joined-zombie',
		expect: 'a thread that joined the reaper reports it dying into a corpse nothing reaps',
		posixOnly: true,
		deadlineMs: ZOMBIE_DEADLINE_MS,
		arrange: async (ctx) => {
			// Runs the script the fork names, for this lock; a node running any other would be reclaimed rather than joined
			const target = await foster(ctx, process.execPath, [CHILD, '--self-pid-file', ctx.lockPath(REAPER_NAME)]);
			mkdirSync(ctx.pidDir, { recursive: true });
			// The reaper lock's version fingerprints this pid, and worker threads share it, so a sibling thread joins
			writeFileSync(ctx.lockPath(REAPER_NAME), `${target}\n${fingerprintVersion(REAPER_NAME, process.pid)}`);
			const logger = collectingLogger();
			const processes = supervisor(ctx, logger, reaperKeep(ctx));
			const state = await processes.start(descriptorFor('matrix-reaper-joined-zombie', [CHILD], { reaper: true }));
			ctx.keep(() => stopQuietly(state.pid, { signal: 'SIGTERM' }));
			ctx.keep(() => stopQuietly(processes.reaper?.pid, { signal: 'SIGTERM' }));
			assert.strictEqual(processes.reaper?.adopted, true, 'the reaper lock must hand this thread the wrapper');
			assert.strictEqual(processes.reaper.pid, target, 'and must join the fostered pid');
			return { observed: processes.reaper, lines: logger.lines, target, processes };
		},
		act: (subject) => killIntoZombie('h-ensure-reaper-joined-zombie', subject.target),
		observe: 'death',
		lines: { warn: /has died with no thread on this node owning it; this thread claimed its PID lock/ },
		// A reaper no keeper holds, as a build before the keeper leaves one: the claim restarts it under a keeper
		then: (subject, ctx) => assertReaperReplaced('h-ensure-reaper-joined-zombie', subject, ctx, subject.target),
	},
	{
		id: 'h-ensure-reaper-joined-alive',
		expect: 'a thread that joined a live reaper reports nothing across the whole state-read cadence',
		posixOnly: true,
		arrange: async (ctx) => {
			const first = await withReaper(ctx, 'matrix-reaper-joined-alive');
			const second = await withReaper(ctx, 'matrix-reaper-joined-alive');
			assert.strictEqual(second.processes.reaper?.adopted, true, 'the second thread must join the reaper');
			return { observed: second.processes.reaper, lines: second.logger.lines, target: first.processes.reaper.pid };
		},
		observe: 'no-death',
		silent: { warn: /sidecar reaper/, error: /sidecar reaper/ },
	},
	{
		id: 'h-ensure-reaper-foreign-node',
		expect: 'a reaper lock naming an unrelated node process launches a reaper rather than signalling it',
		posixOnly: true,
		arrange: async (ctx) => {
			const stranger = await holder(ctx, process.execPath, ['-e', LONG_RUNNING]);
			mkdirSync(ctx.pidDir, { recursive: true });
			// A previous boot's fingerprint makes the version-mismatch restart live; only argv tells the stranger from the reaper
			writeFileSync(ctx.lockPath(REAPER_NAME), `${stranger}\n${fingerprintVersion(REAPER_NAME, 1)}`);
			const { processes, logger } = await withReaper(ctx, 'matrix-reaper-foreign');
			assert.strictEqual(
				isProcessAlive(stranger),
				true,
				'h-ensure-reaper-foreign-node: a node process running another script was signalled off the reaper lock'
			);
			assert.strictEqual(processes.reaper?.adopted, false, 'an unrelated node was joined as the reaper');
			assert.notStrictEqual(processes.reaper.pid, stranger, 'and the reaper must be a process of its own');
			return { observed: processes.reaper, lines: logger.lines, target: stranger };
		},
		observe: 'no-death',
		quietMs: OWNED_QUIET_MS,
	},
	{
		id: 'h-reaper-death-orphans-sidecars',
		expect:
			'a reaper that dies after its keeper leaves the sidecars running, and the next start launches a replacement',
		posixOnly: true,
		arrange: async (ctx) => {
			const first = await withReaper(ctx, 'matrix-reaper-orphans');
			assert.strictEqual(first.processes.reaper?.adopted, false, 'the first start launches the reaper');
			return {
				observed: first.processes.reaper,
				lines: first.logger.lines,
				target: first.processes.reaper.pid,
				keeper: readPidLock(ctx.lockPath(REAPER_NAME))?.keeper,
				sidecarPid: first.state.pid,
			};
		},
		// The keeper first, so nothing restarts the reaper and nothing records how it ended
		act: async (subject) => {
			process.kill(subject.keeper, 'SIGKILL');
			await waitFor(() => !isProcessAlive(subject.keeper), { message: 'the reaper`s keeper outlived a SIGKILL' });
			process.kill(subject.target, 'SIGKILL');
		},
		observe: 'death',
		lines: { warn: /died with its keeper \(pid \d+\) gone/ },
		then: async (subject, ctx) => {
			assert.strictEqual(isProcessAlive(subject.sidecarPid), true, 'the sidecar must outlive the reaper watching it');
			assert.strictEqual(subject.observed.started, false, 'a reaper nothing will restart is reported started');
			const { processes } = await withReaper(ctx, 'matrix-reaper-orphans');
			assert.strictEqual(processes.reaper?.adopted, false, 'a later start must launch a replacement reaper');
			assert.notStrictEqual(processes.reaper.pid, subject.target, 'and it must be a new process');
		},
	},

	// Cells no run on one posix machine can construct
	{
		id: 'x-windows-any',
		expect: 'every supervisor against every death on win32',
		unreachable:
			'needs a second OS: processIdentity.ts reads no identity on win32, so every identification degrades to unknown and the lock keeps its legacy version-mismatch restart',
	},
	{
		id: 'x-true-lock-race',
		expect: 'two threads inside the PID lock at once, one told to spawn and the other adopting the pid it names',
		unreachable:
			'every cell here runs on one event loop, so no two calls are ever inside acquirePidFileLock together; its link(2) gate decides that race, which the held-gate cases in unitTests/security/processSupervisor/pidFileLock.test.js and pidLockClaim.test.js bind instead; the sixteen-worker-thread race in sidecarRace.test.js catches a missing gate in some runs only',
	},
	{
		id: 'x-claim-arbiter-multi-winner',
		expect: 'the claim arbitrating a death two threads reached at the same instant',
		unreachable:
			'a multi-winner needs real OS threads racing one name; every cell here runs on one event loop, where unlinkSync is exclusive by construction, so replacing the claim rename with an unlink fails nothing in this table; the rename is kept for a gate broken under a stalled caller, and no test fails without it, the eight-worker-thread rounds in unitTests/security/processSupervisor/pidLockClaim.test.js included',
	},
	{
		id: 'x-darwin-poll-cadence',
		expect: 'one ps per wrapper per ten seconds rather than one per second',
		unreachable:
			'the cost behind DARWIN_STATE_READ_EVERY needs a clock or an execFileSync seam; reverting the cadence makes these tests pass faster, not fail, so no assertion here can catch it',
	},
];

describe('the supervision matrix', function () {
	failOnSurvivors();
	this.timeout(30_000);

	let workDir;
	let component;
	let ctx;

	before(async () => {
		_setPollIntervalForTests(POLL_MS);
		_setIdentifyDeadlineForTests(IDENTIFY_DEADLINE_MS);
		_setTimingForTests(TEST_TIMING);
		workDir = mkdtempSync(join(tmpdir(), 'supervision-matrix-'));
		// Through the real loader, so the component's own child_process import is what gets substituted
		component = await scopedImport(COMPONENT, { mode: 'vm-current-context' });
	});

	after(() => {
		_setPollIntervalForTests();
		_setIdentifyDeadlineForTests();
		_setTimingForTests();
		rmSync(workDir, { recursive: true, force: true });
	});

	beforeEach(() => {
		const pidDir = join(env.getHdbBasePath(), 'pids');
		// The locks and descriptors are the only record of what this test started, so reap before removing them
		reapPidDir(pidDir);
		rmSync(pidDir, { recursive: true, force: true });
		const stops = [];
		ctx = {
			pidDir,
			workDir,
			component,
			open: true,
			lockPath: (name) => join(pidDir, `${name}.pid`),
			keep: (stop) => stops.push(stop),
			stops,
		};
	});

	afterEach(async () => {
		ctx.open = false;
		for (const stop of ctx.stops.reverse()) await stop();
		reapPidDir(ctx.pidDir);
		rmSync(ctx.pidDir, { recursive: true, force: true });
	});

	for (const cell of MATRIX) {
		if (cell.unreachable) {
			it.skip(`${cell.id}: ${cell.expect} [unreachable: ${cell.unreachable}]`);
			continue;
		}
		it(`${cell.id}: ${cell.expect}`, async function () {
			if (cell.posixOnly && process.platform === 'win32') this.skip();
			const subject = await cell.arrange(ctx);
			// Only where the death is delivered below: a cell whose child dies on its own may have exited already
			if (cell.act) {
				assert.ok(!subject.observed.exited, `${cell.id}: nothing has died yet`);
				await cell.act(subject, ctx);
			}
			if (cell.observe === 'death') {
				// The line is logged with `exited`, and outlasts it: a restart clears `exited` within one short backoff
				await waitFor(() => subject.observed.exited === true || deathLogged(subject), {
					timeout: cell.deadlineMs ?? DEATH_DEADLINE_MS,
					interval: 25,
					message: `${cell.id}: the death went unnoticed`,
				});
			} else {
				await assertQuiet(cell.id, subject, cell.quietMs ?? JOINED_QUIET_MS);
			}
			for (const [level, pattern] of Object.entries(cell.lines ?? {}))
				assertLine(cell.id, subject.lines, level, pattern);
			for (const [level, pattern] of Object.entries(cell.silent ?? {}))
				assertNoLine(cell.id, subject.lines, level, pattern);
			await cell.then?.(subject, ctx);
		});
	}
});
