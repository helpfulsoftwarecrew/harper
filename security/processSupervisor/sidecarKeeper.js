'use strict';

// The parent of a sidecar that scope.processes starts on Linux and darwin, run by bare node from its path.
// Its launcher exits at once so init adopts it; it then reaps the sidecar, restarts a crash and records each death.
const { execFileSync, spawn } = require('node:child_process');
const { linkSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } = require('node:fs');
const { randomUUID } = require('node:crypto');
const { setTimeout: delay } = require('node:timers/promises');

/** What a supervisor sends on the way down; each is forwarded, and nothing is started again after one. */
const STOP_SIGNALS = ['SIGTERM', 'SIGINT', 'SIGHUP'];
/** How long a child started under a lock this keeper lost gets after SIGTERM before SIGKILL. */
const TERM_GRACE_MS = 5000;
/** pidFileLock.ts's gate suffix and how old a live holder's gate must be to count as abandoned, so both sides agree. */
const GATE_SUFFIX = '.claiming';
const BREAKER_SUFFIX = '.breaking';
const GATE_WAIT_MS = 30_000;
const GATE_RETRY_MS = 1;
const OUTCOMES = new Set(['released', 'restarting', 'gave-up', 'gone', 'taken', 'failed']);

function errorMessage(error) {
	return error instanceof Error ? error.message : String(error);
}

function unlinkQuietly(path) {
	try {
		unlinkSync(path);
	} catch {
		// Absent is the outcome asked for
	}
}

/** This process's environment without its locale, which ps would read before anything set here; a bogus one is C. */
function withoutLocale() {
	return Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'LANG' && !key.startsWith('LC_')));
}

/** The start time in the C locale and UTC, so a keeper and a thread read one start time as the same string. */
function startTimeEnv() {
	return { ...withoutLocale(), LC_ALL: 'C', TZ: 'UTC' };
}

/** A command line in UTF-8 whatever the caller's locale: darwin's ps escapes its bytes outside ASCII in C. */
function commandLineEnv() {
	return { ...withoutLocale(), LC_CTYPE: 'UTF-8' };
}

function ps(pid, fields) {
	return execFileSync('ps', ['-p', String(pid), '-o', fields], {
		encoding: 'utf-8',
		timeout: 2000,
		stdio: ['ignore', 'pipe', 'ignore'],
		env: startTimeEnv(),
	}).trim();
}

let bootId;
/** The ticks in /proc/<pid>/stat count from boot, and a lock outlives one, so the boot's id goes with them. */
function linuxBootId() {
	if (bootId === undefined) {
		try {
			bootId = readFileSync('/proc/sys/kernel/random/boot_id', 'utf-8').trim() || null;
		} catch {
			bootId = null;
		}
	}
	return bootId;
}

const GONE = Object.freeze({ alive: false, ppid: null, started: null });

/**
 * Liveness, parent and start time from one read; a zombie holds its pid and runs nothing, so it is gone. Both sides take
 * this read, since the keeper records a start time and a thread compares it; a thread passes its own `ps` as `run`.
 */
function inspect(pid, run = ps) {
	// Non-positive values are process groups to kill(2), so asking would answer for the group
	if (!Number.isInteger(pid) || pid <= 0) return GONE;
	try {
		process.kill(pid, 0);
	} catch (error) {
		if (error.code !== 'EPERM') return GONE;
	}
	const unread = { alive: true, ppid: null, started: null };
	try {
		if (process.platform === 'linux') {
			const stat = readFileSync(`/proc/${pid}/stat`, 'utf-8');
			// comm is parenthesised and may hold spaces and parens, so the fields follow the LAST ')'
			const fields = stat
				.slice(stat.lastIndexOf(')') + 1)
				.trim()
				.split(/\s+/);
			if ((fields[0] ?? '').startsWith('Z')) return GONE;
			const boot = linuxBootId();
			const ticks = fields[19];
			return { alive: true, ppid: toPid(fields[1]), started: boot && ticks ? `${boot}:${ticks}` : null };
		}
		if (process.platform === 'darwin') {
			const [state, ppid, ...lstart] = run(pid, 'state=,ppid=,lstart=').split(/\s+/);
			if (!state || state.startsWith('Z')) return GONE;
			return { alive: true, ppid: toPid(ppid), started: lstart.length === 5 ? lstart.join(' ') : null };
		}
	} catch {
		// Liveness was answered by kill(pid, 0); what cannot be read is "cannot tell"
	}
	return unread;
}

function toPid(field) {
	const pid = Number.parseInt(field ?? '', 10);
	return Number.isInteger(pid) && pid > 0 ? pid : null;
}

function isAlive(pid) {
	return inspect(pid).alive;
}

/** When `pid` started, comparable only for equality, or null when it is gone or cannot be read. */
function startedAt(pid) {
	return inspect(pid).started;
}

function parentOf(pid) {
	return inspect(pid).ppid;
}

/**
 * pidFileLock.ts's readPidLock, mirrored step for step: blank is no lock, pid and version come from the trimmed lines,
 * a claim opens with a newline and carries its claimant and token, and a keeper's commit carries its record on line three.
 */
function readLock(path) {
	let content;
	try {
		content = readFileSync(path, 'utf-8');
	} catch {
		return null;
	}
	if (content.trim() === '') return null;
	const lines = content.split('\n');
	const [pidLine, versionLine] = content.trim().split('\n');
	const pid = Number.parseInt(pidLine, 10);
	if (!Number.isInteger(pid)) return null;
	const claimant = Number.parseInt(lines[2] ?? '', 10);
	// A claim's second line is its claimant, not a version
	const claim = content.startsWith('\n');
	const version = claim ? 0 : versionLine === undefined ? 0 : Number.parseInt(versionLine, 10);
	const lock = {
		pid,
		version,
		claimant: Number.isInteger(claimant) ? claimant : null,
		token: claim ? (lines[3] ?? '') : '',
	};
	if (claim) return lock;
	try {
		const record = JSON.parse(lines[2] ?? '');
		if (typeof record?.token === 'string') lock.token = record.token;
		if (Number.isInteger(record?.host)) lock.host = record.host;
		if (Number.isInteger(record?.keeper) && record.keeper > 0) lock.keeper = record.keeper;
		if (Array.isArray(record?.keeperArgv) && record.keeperArgv.every((part) => typeof part === 'string'))
			lock.keeperArgv = record.keeperArgv;
		if (typeof record?.started === 'string' && record.started !== '') lock.started = record.started;
	} catch {
		// No record: a lock Harper's own spawn wrote, which carries a pid and a version only
	}
	return lock;
}

/** Temp and rename, so a reader finds the claim or the commit and never an empty file between them. */
function writeLock(path, token, content, stillHeld) {
	const temp = `${path}.${token}.tmp`;
	writeFileSync(temp, content, 'utf-8');
	if (!stillHeld()) {
		unlinkQuietly(temp);
		return false;
	}
	try {
		renameSync(temp, path);
	} catch (error) {
		unlinkQuietly(temp);
		throw error;
	}
	return true;
}

let gateSerial = 0;
let ownStart = null;

/** pidFileLock.ts's rule: `pid` is still the process that wrote `started`, unreadable on either side counting as it. */
function stillHeldBy(pid, started) {
	if (pid !== process.pid && !isAlive(pid)) return false;
	if (!started) return true;
	ownStart ??= startedAt(process.pid);
	const now = pid === process.pid ? ownStart : startedAt(pid);
	return now === null || now === started;
}

/** Link the gate naming this process, its start and a nonce of this holding; the nonce, or null when it is held. */
function linkGate(gate) {
	const nonce = randomUUID();
	const temp = `${gate}.${process.pid}.${++gateSerial}.${nonce}`;
	ownStart ??= startedAt(process.pid);
	try {
		writeFileSync(temp, `${process.pid}\n${ownStart ?? ''}\n${nonce}`, 'utf-8');
		linkSync(temp, gate);
		return nonce;
	} catch (error) {
		if (error?.code !== 'EEXIST') throw error;
		return null;
	} finally {
		unlinkQuietly(temp);
	}
}

function ageOf(path) {
	try {
		return Math.max(0, Date.now() - statSync(path).mtimeMs);
	} catch {
		return 0;
	}
}

/** pidFileLock.ts's breakable: a dead or reissued holder's file may go at once, a live one's once it is old. */
function breakable(path, abandonAfterMs) {
	let holder;
	let holderStarted;
	try {
		const [pidLine, startLine] = readFileSync(path, 'utf-8').split('\n');
		holder = Number.parseInt(pidLine, 10);
		holderStarted = startLine || undefined;
	} catch {
		// Unreadable is "cannot tell", never "not ours": clearing it would take a gate linked since
		return false;
	}
	if (Number.isInteger(holder) && !stillHeldBy(holder, holderStarted)) return true;
	return ageOf(path) >= abandonAfterMs;
}

function nonceOf(path) {
	try {
		return readFileSync(path, 'utf-8').split('\n')[2] ?? null;
	} catch {
		return null;
	}
}

/** Remove what `path` holds only while it is still this holding's: one broken and retaken since is its taker's. */
function releaseHeld(path, nonce) {
	if (nonceOf(path) === nonce) unlinkQuietly(path);
}

/** pidFileLock.ts's takeGate, mirrored: a gate is broken only while holding the breaker file beside it. */
function takeGate(path, abandonAfterMs) {
	const gate = `${path}${GATE_SUFFIX}`;
	const nonce = linkGate(gate);
	if (nonce !== null) return nonce;
	if (!breakable(gate, abandonAfterMs)) return null;
	const breaker = `${gate}${BREAKER_SUFFIX}`;
	let breaking = linkGate(breaker);
	if (breaking === null) {
		if (!breakable(breaker, abandonAfterMs)) return null;
		unlinkQuietly(breaker);
		breaking = linkGate(breaker);
		if (breaking === null) return null;
	}
	try {
		// Judged again while breaking: the gate read before may be one a sibling linked since
		if (!breakable(gate, abandonAfterMs)) return null;
		unlinkQuietly(gate);
		return linkGate(gate);
	} finally {
		releaseHeld(breaker, breaking);
	}
}

/** Run `decide` on the lock as it stands while holding its gate; `decide` must not await, and may ask if it still holds it. */
async function underGate(path, decide, abandonAfterMs = GATE_WAIT_MS) {
	const gate = `${path}${GATE_SUFFIX}`;
	for (;;) {
		const nonce = takeGate(path, abandonAfterMs);
		if (nonce !== null) {
			try {
				return decide(readLock(path), () => nonceOf(gate) === nonce);
			} finally {
				releaseHeld(gate, nonce);
			}
		}
		await delay(GATE_RETRY_MS);
	}
}

const recordPath = (lockPath) => `${lockPath}.exit`;

/** The last death this lock's keeper recorded, or null for none and for one this version cannot read. */
function readRecord(lockPath) {
	try {
		const record = JSON.parse(readFileSync(recordPath(lockPath), 'utf-8'));
		if (typeof record?.token !== 'string' || !OUTCOMES.has(record.outcome) || !Number.isInteger(record.pid))
			return null;
		return record;
	} catch {
		return null;
	}
}

/** Temp and rename, so a thread reads the previous record or this one and never half of either. */
function writeRecord(lockPath, record) {
	const file = recordPath(lockPath);
	const temp = `${file}.${process.pid}.tmp`;
	try {
		writeFileSync(temp, JSON.stringify(record), 'utf-8');
		renameSync(temp, file);
	} catch {
		// A thread that finds no record answers from the lock instead, which costs precision and not the process
		unlinkQuietly(temp);
	}
}

/**
 * A stop signal or a clean exit is somebody shutting it down; restarting into one fights the operator. The lifecycle
 * grades a direct child's exit and the forked reaper's by this too.
 */
function isDeliberate(code, signal) {
	return signal ? STOP_SIGNALS.includes(signal) : code === 0;
}

function parseArgs(argv) {
	const split = argv.indexOf('--');
	const flags = split === -1 ? argv : argv.slice(0, split);
	const options = {
		lock: '',
		token: '',
		version: 0,
		hostPid: 0,
		restarts: 0,
		restartMax: 0,
		restartBaseMs: 0,
		restartCapMs: 0,
		stableMs: 0,
		termGraceMs: TERM_GRACE_MS,
		argv: split === -1 ? [] : argv.slice(split + 1),
	};
	const int = (value) => Number.parseInt(value, 10);
	for (let i = 0; i + 1 < flags.length; i += 2) {
		const value = flags[i + 1];
		switch (flags[i]) {
			case '--lock':
				options.lock = value;
				break;
			case '--token':
				options.token = value;
				break;
			case '--version':
				options.version = int(value);
				break;
			case '--host-pid':
				options.hostPid = int(value);
				break;
			case '--restarts':
				options.restarts = int(value);
				break;
			case '--restart-max':
				options.restartMax = int(value);
				break;
			case '--restart-base-ms':
				options.restartBaseMs = int(value);
				break;
			case '--restart-cap-ms':
				options.restartCapMs = int(value);
				break;
			case '--stable-ms':
				options.stableMs = int(value);
				break;
			// Test-only: a suite shortens the grace a lost commit's child gets, which no thread passes
			case '--term-grace-ms':
				options.termGraceMs = int(value);
				break;
		}
	}
	return options;
}

function blankRecord(options, keeper) {
	return {
		token: options.token,
		keeper,
		pid: 0,
		code: null,
		signal: null,
		outcome: 'failed',
		restarts: options.restarts,
		waitMs: 0,
		at: Date.now(),
		released: false,
	};
}

/** Start the keeper and exit, so the thread that spawned this reaps it at once and init adopts the keeper. */
function launch(flags) {
	const keeper = spawn(process.execPath, [__filename, '--keep', ...flags], { stdio: 'ignore' });
	if (keeper.pid) process.exit(0);
	keeper.once('error', (error) => {
		const options = parseArgs(flags);
		writeRecord(options.lock, {
			...blankRecord(options, 0),
			error: `its keeper could not be started: ${error.message}`,
		});
		process.exit(1);
	});
}

async function stopChild(child, exited, graceMs) {
	child.kill('SIGTERM');
	const graced = await Promise.race([exited, delay(graceMs, null, { ref: false })]);
	if (graced === null) child.kill('SIGKILL');
	return exited;
}

/**
 * Start the process, commit its pid under the claim's token, and answer each death: a deliberate one releases the
 * lock, a crash is restarted with backoff while the lock still carries this keeper's token. Resolves to an exit code.
 */
async function keep(options) {
	let stopping = null;
	let child = null;
	const woken = new AbortController();
	for (const signal of STOP_SIGNALS) {
		process.on(signal, () => {
			stopping ??= signal;
			if (child && child.exitCode === null && child.signalCode === null) child.kill(signal);
			woken.abort();
		});
	}
	const keeperArgv = [process.execPath, __filename, '--keep', '--lock', options.lock, '--token', options.token];
	let restarts = options.restarts;
	let last = { pid: 0, code: null, signal: null };
	const record = (fields) =>
		writeRecord(options.lock, { ...blankRecord(options, process.pid), ...last, restarts, at: Date.now(), ...fields });
	// The record beside the lock is its holder's: written inside the gate, and only while the lock is gone or carries
	// this token, so a keeper whose lock was taken never writes over the record of the keeper that took it
	const release = async (fields) => {
		try {
			await underGate(options.lock, (held) => {
				if (held !== null && held.token !== options.token) return;
				const gone = held === null && fields.outcome !== 'failed' ? { outcome: 'gone' } : {};
				record({ ...fields, ...gone, released: held !== null });
				if (held !== null) unlinkQuietly(options.lock);
			});
		} catch (error) {
			record({ ...fields, error: fields.error ?? errorMessage(error) });
		}
	};
	// A lock that stopped carrying this token was taken or removed; nothing is started under a lost lock
	const lost = () =>
		underGate(options.lock, (held) => {
			if (held?.token === options.token) return false;
			if (held === null) record({ outcome: 'gone' });
			return true;
		});

	for (;;) {
		const started = spawn(options.argv[0], options.argv.slice(1), { stdio: 'ignore' });
		const spawnedAt = Date.now();
		child = started;
		// Kept, not once: a second 'error', from a kill that fails, would otherwise end the keeper
		const failed = new Promise((resolve) => started.on('error', resolve));
		if (!started.pid) {
			last = { pid: 0, code: null, signal: null };
			await release({ outcome: 'failed', error: errorMessage(await failed) });
			return 1;
		}
		const pid = started.pid;
		const exited = new Promise((resolve) => started.once('exit', (code, signal) => resolve({ code, signal })));
		// Read before the commit and recorded with it, so the process stays identifiable through an exec
		const startTime = startedAt(pid);
		let committed;
		try {
			committed = await underGate(options.lock, (held, stillHeld) => {
				if (held === null) return 'gone';
				if (held.token !== options.token) return 'taken';
				const lock = { token: options.token, host: options.hostPid, keeper: process.pid, keeperArgv };
				if (startTime !== null) lock.started = startTime;
				const content = `${pid}\n${options.version}\n${JSON.stringify(lock)}\n`;
				// A keeper stalled until its gate was broken writes nothing over what its breaker decided
				return writeLock(options.lock, options.token, content, stillHeld) ? 'written' : 'taken';
			});
		} catch (error) {
			committed = errorMessage(error);
		}
		if (committed !== 'written') {
			// No lock names this process, so nothing but this keeper would ever stop it
			last = { pid, ...(await stopChild(started, exited, options.termGraceMs)) };
			if (committed === 'gone') await lost();
			else if (committed !== 'taken') await release({ outcome: 'failed', error: committed });
			return 0;
		}
		if (stopping !== null) started.kill(stopping);
		last = { pid, ...(await exited) };
		child = null;

		if (stopping !== null || isDeliberate(last.code, last.signal)) {
			await release({ outcome: 'released' });
			return 0;
		}
		// The reaper and the shutdown stop remove the lock before they signal, so a death either causes finds it gone
		if (await lost()) return 0;
		// Past --stable-ms a death is a fresh incident, so the cap bounds a crash loop rather than a lifetime
		if (options.stableMs > 0 && Date.now() - spawnedAt > options.stableMs) restarts = 0;
		if (restarts + 1 > options.restartMax) {
			await release({ outcome: 'gave-up' });
			return 0;
		}
		const backoff = options.restartBaseMs * 2 ** restarts;
		const waitMs = options.restartCapMs > 0 ? Math.min(backoff, options.restartCapMs) : backoff;
		restarts += 1;
		const noted = await underGate(options.lock, (held) => {
			if (held?.token !== options.token) return false;
			record({ outcome: 'restarting', waitMs });
			return true;
		});
		if (!noted && (await lost())) return 0;
		await delay(waitMs, undefined, { signal: woken.signal }).catch(() => {});
		if (stopping !== null) {
			await release({ outcome: 'released' });
			return 0;
		}
		if (await lost()) return 0;
	}
}

module.exports = {
	STOP_SIGNALS,
	commandLineEnv,
	errorMessage,
	inspect,
	isAlive,
	isDeliberate,
	parentOf,
	readLock,
	readRecord,
	recordPath,
	startTimeEnv,
	startedAt,
	underGate,
	unlinkQuietly,
	// For the tests that hold this copy of the gate to pidFileLock.ts's
	GATE_WAIT_MS,
	releaseHeld,
	takeGate,
};

// Executed directly, which is how a thread uses this; required, it only lends its helpers to the reaper
if (require.main === module) {
	const [mode, ...flags] = process.argv.slice(2);
	const options = parseArgs(flags);
	// Nothing of its own goes to stdio: nobody reads it once the thread that launched it is gone
	if (!options.lock || !options.token || options.argv.length === 0) process.exit(2);
	if (mode === '--launch') launch(flags);
	else if (mode === '--keep')
		keep(options).then(
			(code) => process.exit(code),
			(error) => {
				writeRecord(options.lock, { ...blankRecord(options, process.pid), error: errorMessage(error) });
				process.exit(1);
			}
		);
	else process.exit(2);
}
