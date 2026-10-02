// One process per name per node however many threads ask; without a keeper's start time, one that execs is the exception.
// A live holder is adopted or signalled only after ./processIdentity.ts says what it runs, and only under a gate file.

import {
	closeSync,
	linkSync,
	openSync,
	readFileSync,
	renameSync,
	statSync,
	unlinkSync,
	writeFileSync,
	writeSync,
} from 'node:fs';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { threadId } from 'node:worker_threads';

import logger from '../../utility/logging/harper_logger.ts';
import {
	identifyKeeper,
	identifyKept,
	identifyProcess,
	isProcessAlive,
	platformCanIdentifyProcesses,
	startedAt,
	type KeptRecord,
} from './processIdentity.ts';

let ownStart: string | null = null;

/** This process's start time, read until a read succeeds: a claim and a gate carry it, so a reissued pid is told apart. */
function ownStartTime(): string | null {
	ownStart ??= startedAt(process.pid);
	return ownStart;
}

/**
 * Whether `pid` is still the process that wrote `started` beside it. This process needs no liveness read, and a start
 * time that cannot be read on either side leaves it counted as the writer.
 */
function stillHeldBy(pid: number, started: string | undefined): boolean {
	if (pid !== process.pid && !isProcessAlive(pid)) return false;
	if (!started) return true;
	const now = pid === process.pid ? ownStartTime() : startedAt(pid);
	return now === null || now === started;
}

/** The keeper's writeLock leaves no temp file behind a commit that did not land, and neither does this. */
function unlinkQuietly(path: string): void {
	try {
		unlinkSync(path);
	} catch {
		// Absent is the outcome asked for
	}
}

/** How long ago `path` was last written, or 0 when it cannot be read, which never reads as old. */
function ageOf(path: string): number {
	try {
		return Math.max(0, Date.now() - statSync(path).mtimeMs);
	} catch {
		return 0;
	}
}

/** The lock's two lines: pid first, version second, tolerant of a file that carries only the first. */
function parsePidFile(content: string): { pid: number; version: number } {
	const lines = content.trim().split('\n');
	const pid = Number.parseInt(lines[0], 10);
	const version = lines.length > 1 ? parseInt(lines[1], 10) : 0;
	return { pid, version };
}

/** A lock as it stands: a claim carries its claimant, token and the claimant's start, a commit its record on line three. */
export interface PidLock extends KeptRecord {
	pid: number;
	version: number;
	claimant: number | null;
	claimantStarted?: string;
	token: string;
	host?: number;
}

/** Line three of a keeper's commit, or nothing for a lock Harper's own spawn wrote. */
function parseKeeperRecord(line: string | undefined): Partial<PidLock> {
	let record: any;
	try {
		record = JSON.parse(line ?? '');
	} catch {
		return {};
	}
	const parsed: Partial<PidLock> = {};
	if (typeof record?.token === 'string') parsed.token = record.token;
	if (Number.isInteger(record?.host)) parsed.host = record.host;
	if (Number.isInteger(record?.keeper) && record.keeper > 0) parsed.keeper = record.keeper;
	if (Array.isArray(record?.keeperArgv) && record.keeperArgv.every((part: unknown) => typeof part === 'string'))
		parsed.keeperArgv = record.keeperArgv;
	if (typeof record?.started === 'string' && record.started !== '') parsed.started = record.started;
	return parsed;
}

function parseLock(content: string): PidLock {
	const lines = content.split('\n');
	// Line three, written by whoever created the file and left alone by everyone after
	const claimant = Number.parseInt(lines[2] ?? '', 10);
	// A claim opens with a newline, so its lines are one further down than a commit's
	const claim = content.startsWith('\n');
	const token = claim ? (lines[3] ?? '') : '';
	const { pid, version } = parsePidFile(content);
	return {
		pid,
		// A claim's second line is its claimant, not a version
		version: claim ? 0 : version,
		claimant: Number.isInteger(claimant) ? claimant : null,
		token,
		...(claim && lines[4] ? { claimantStarted: lines[4] } : {}),
		...(claim ? {} : parseKeeperRecord(lines[2])),
	};
}

/** The lock at `path`, or null when it is absent, empty or does not parse. */
export function readPidLock(path: string): PidLock | null {
	let content: string;
	try {
		content = readFileSync(path, 'utf-8');
	} catch {
		return null;
	}
	if (content.trim() === '') return null;
	const lock = parseLock(content);
	return Number.isInteger(lock.pid) ? lock : null;
}

/**
 * What to do about a lock that already exists. `unknown` is "not established", never "not ours", so it
 * waits for a real verdict until the identification deadline and is adopted only after it.
 */
type Verdict =
	| { act: 'take'; stop?: number; token?: string }
	| { act: 'wait'; pollMs?: number }
	| { act: 'adopt'; pid: number; version: number };

function adjudicateLock(
	held: PidLock,
	against: {
		expectedCommand: string;
		expectedScript: string | undefined;
		requestedVersion: number | undefined;
		required: readonly string[] | undefined;
		expired: boolean;
		overdue: boolean;
		claimAgeMs: number;
		abandonAfterMs: number;
		notes: string[];
	}
): Verdict {
	const { expectedCommand, expectedScript, requestedVersion, required, expired, overdue, notes } = against;

	// A claim in flight: parsePidFile trims the claim's leading newline, so `\n0\n<pid>` reads as pid 0. Its claimant,
	// on line three, and that claimant's start time, on line five, tell one in flight from one a dead process left.
	if (held.pid === 0 || isNaN(held.pid)) {
		if (held.claimant === null) {
			notes.push('reclaimed a lock recording no live process and no claimant');
			return { act: 'take' };
		}
		if (!stillHeldBy(held.claimant, held.claimantStarted)) {
			notes.push(`reclaimed an unfinished claim from pid ${held.claimant}, which is gone or now another process`);
			return { act: 'take' };
		}
		// Worker threads share one pid, so a live claimant's claim is waited on until the claim itself is old: a
		// caller's own long wait says nothing about a sibling's claim written a moment ago
		if (against.claimAgeMs < against.abandonAfterMs) return { act: 'wait', pollMs: CLAIM_POLL_MS };
		notes.push(`took over a claim pid ${held.claimant} left unfinished for ${against.claimAgeMs}ms`);
		return { act: 'take' };
	}

	if (!isProcessAlive(held.pid)) {
		// A live keeper is between a death and the restart it owes, and taking the lock would start a second
		if (held.keeper !== undefined && !overdue && identifyKeeper(held.keeper, held.keeperArgv ?? []) !== 'differs')
			return { act: 'wait', pollMs: KEEPER_POLL_MS };
		notes.push(`reclaimed a lock naming pid ${held.pid}, which nothing holds`);
		return { act: 'take' };
	}

	// A keeper's record identifies its child through an exec, by start time or by the keeper as its parent
	const identification =
		held.keeper !== undefined || held.started !== undefined
			? identifyKept(held.pid, expectedCommand, expectedScript, held, required)
			: identifyProcess(held.pid, expectedCommand, expectedScript, required);

	if (identification === 'differs') {
		notes.push(`the lock named live pid ${held.pid}, which is running something else; took it and signalled nothing`);
		return { act: 'take' };
	}

	// Cannot tell yet. Wait rather than guess; a pid that cannot be identified is most likely ours.
	if (identification === 'unknown' && !expired && platformCanIdentifyProcesses()) return { act: 'wait' };

	if (requestedVersion != null && requestedVersion !== held.version) {
		// Only a positive match may authorize the restart, except where processIdentity reads nothing:
		// Windows keeps the legacy behaviour rather than losing upgrades entirely.
		if (identification === 'match' || !platformCanIdentifyProcesses()) {
			notes.push(`replacing pid ${held.pid} on a version change (${held.version} -> ${requestedVersion})`);
			return { act: 'take', stop: held.pid };
		}
		notes.push(
			`not restarting pid ${held.pid} on a version change (${held.version} -> ${requestedVersion}): it was not ` +
				`positively identified as running ${expectedScript ? `${expectedCommand} ${expectedScript}` : expectedCommand}`
		);
	}

	return { act: 'adopt', pid: held.pid, version: held.version };
}

// IDENTIFY_DEADLINE_MS bounds "cannot tell yet" before an unidentified holder is adopted. CLAIM_TIMEOUT_MS is how old
// a live holder's claim or gate must be before it counts as abandoned, and twice it bounds a call before it throws.
const IDENTIFY_DEADLINE_MS = 500;
// Exported for the test that holds the keeper's copy of the abandon age to this one
export const CLAIM_TIMEOUT_MS = 30_000;
const CLAIM_RETRY_MS = 5;
/** How often a lock waiting out a keeper's backoff looks again, since each look forks `ps` on darwin. */
const KEEPER_POLL_MS = 50;
/** How often a lock waiting on a live claim looks again, since each look links and removes the gate. */
const CLAIM_POLL_MS = 50;

let identifyDeadlineMs = IDENTIFY_DEADLINE_MS;

// Test-only: a suite adopting many bare-name holders shortens the wait. No argument restores the shipped
// deadline; the one in effect is returned, so a test can pin what ships.
export function _setIdentifyDeadlineForTests(ms: number = IDENTIFY_DEADLINE_MS): number {
	identifyDeadlineMs = ms;
	return identifyDeadlineMs;
}

// A lock on the lock: removing a stale lock and creating its replacement are two syscalls, so both happen
// while one thread holds this file, linked with link(2) so it names its holder from the instant it exists.
const GATE_SUFFIX = '.claiming';
/** The second file a thread holds while it breaks a gate, beside the gate. */
const BREAKER_SUFFIX = '.breaking';
let gateSerial = 0;

/** Link `gate` naming this process, its start time and a nonce of this holding; null when another holds it. */
function linkGate(gate: string): string | null {
	const nonce = randomUUID();
	const temp = `${gate}.${process.pid}.${++gateSerial}.${nonce}`;
	try {
		writeFileSync(temp, `${process.pid}\n${ownStartTime() ?? ''}\n${nonce}`, 'utf-8');
		linkSync(temp, gate);
		return nonce;
	} catch (error: any) {
		if (error?.code !== 'EEXIST') throw error;
		return null;
	} finally {
		try {
			unlinkSync(temp);
		} catch {
			// Absent is the outcome asked for
		}
	}
}

/**
 * Whether the file a holder linked at `path` may be removed: its holder is dead, is a later process under a reissued
 * pid, or has held it for `abandonAfterMs`. One that cannot be read is "cannot tell", never "not ours".
 */
function breakable(path: string, abandonAfterMs: number): boolean {
	let holder: number;
	let holderStarted: string | undefined;
	try {
		const [pidLine, startLine] = readFileSync(path, 'utf-8').split('\n');
		holder = Number.parseInt(pidLine, 10);
		holderStarted = startLine || undefined;
	} catch {
		return false;
	}
	if (Number.isInteger(holder) && !stillHeldBy(holder, holderStarted)) return true;
	return ageOf(path) >= abandonAfterMs;
}

/** The nonce a file linked by linkGate carries, or null when it is gone. */
function nonceOf(path: string): string | null {
	try {
		return readFileSync(path, 'utf-8').split('\n')[2] ?? null;
	} catch {
		return null;
	}
}

/** Remove what `path` holds only while it is still this holding's: one broken and retaken since is its taker's. */
function release(path: string, nonce: string): void {
	try {
		if (nonceOf(path) === nonce) unlinkSync(path);
	} catch {
		// Already gone, which is the outcome asked for
	}
}

/**
 * Take the gate, breaking a breakable one (with `force`, a live one, for an exit handler that cannot wait) only while
 * holding a second file linked beside it, so no thread removes a gate a sibling linked since. The nonce, or null.
 */
function takeGate(pidFilePath: string, abandonAfterMs: number, force: boolean): string | null {
	const gate = `${pidFilePath}${GATE_SUFFIX}`;
	const nonce = linkGate(gate);
	if (nonce !== null) return nonce;
	if (!force && !breakable(gate, abandonAfterMs)) return null;

	const breaker = `${gate}${BREAKER_SUFFIX}`;
	let breaking = linkGate(breaker);
	if (breaking === null) {
		// A breaker left by a dead or long-stalled thread is broken as a gate is; only that step races another breaker
		if (!breakable(breaker, abandonAfterMs)) return null;
		try {
			unlinkSync(breaker);
		} catch {
			// A sibling cleared it first
		}
		breaking = linkGate(breaker);
		if (breaking === null) return null;
	}
	try {
		// Judged again while breaking: the gate read before may be one a sibling linked since
		if (!force && !breakable(gate, abandonAfterMs)) return null;
		try {
			unlinkSync(gate);
		} catch {
			// Released by its holder meanwhile
		}
		return linkGate(gate);
	} finally {
		release(breaker, breaking);
	}
}

/**
 * Hold the gate for `decide`, which must not block, handing it a check that the gate is still this holding's for a
 * write a stall could have outlived. null means the gate was not free.
 */
function underGate<T>(
	pidFilePath: string,
	abandonAfterMs: number,
	force: boolean,
	decide: (stillHeld: () => boolean) => T
): T | null {
	const nonce = takeGate(pidFilePath, abandonAfterMs, force);
	if (nonce === null) return null;
	const gate = `${pidFilePath}${GATE_SUFFIX}`;
	try {
		return decide(() => nonceOf(gate) === nonce);
	} finally {
		release(gate, nonce);
	}
}

/** What a lock attempt returns: pid 0 and the claim's token when the caller should spawn, or a holder to adopt. */
export interface LockResult {
	pid: number;
	version: number;
	token?: string;
}

// Returns pid 0 when the caller should spawn, or the pid and version of an identified holder to adopt
export function acquirePidFileLock(
	pidFilePath: string,
	expectedCommand: string,
	expectedScript: string | undefined,
	requestedVersion?: number,
	timeoutMs = CLAIM_TIMEOUT_MS,
	retryDelay = CLAIM_RETRY_MS,
	/** Arguments the holder must carry in order, which narrows a singleton to the lock it was started for. */
	required?: readonly string[]
): LockResult {
	const { pid, version } = acquirePidFileClaim(
		pidFilePath,
		expectedCommand,
		expectedScript,
		requestedVersion,
		timeoutMs,
		retryDelay,
		required
	);
	return { pid, version };
}

/** acquirePidFileLock with the claim's token, which the caller commits its pid under (commitPidFileLock). */
export function acquirePidFileClaim(
	pidFilePath: string,
	expectedCommand: string,
	expectedScript: string | undefined,
	requestedVersion?: number,
	timeoutMs = CLAIM_TIMEOUT_MS,
	retryDelay = CLAIM_RETRY_MS,
	required?: readonly string[]
): LockResult {
	// Accumulated rather than logged per attempt: a lock resolved on the fourth try would otherwise
	// report the first three inconclusive looks as if each were a decision.
	const notes: string[] = [];
	const deadlines = lockDeadlines(timeoutMs);
	try {
		for (;;) {
			const result = attemptPidFileLock(
				pidFilePath,
				expectedCommand,
				expectedScript,
				requestedVersion,
				deadlines,
				timeoutMs,
				required,
				notes
			);
			if (typeof result !== 'number') return result;
			// Slept rather than spun: a thread waiting out a sibling's claim holds no CPU while it waits
			Atomics.wait(PAUSE, 0, 0, Math.max(retryDelay, result));
		}
	} finally {
		for (const note of notes) logger.warn(`${pidFilePath}: ${note}`);
	}
}

const PAUSE = new Int32Array(new SharedArrayBuffer(4));

/**
 * acquirePidFileLock for a caller that can await: it yields between attempts rather than sleeping the thread, since a
 * claim a keeper has yet to commit stays open across two node starts.
 */
export async function acquirePidFileLockAsync(
	pidFilePath: string,
	expectedCommand: string,
	expectedScript: string | undefined,
	requestedVersion?: number,
	timeoutMs = CLAIM_TIMEOUT_MS,
	retryDelay = CLAIM_RETRY_MS,
	/** Arguments the holder must carry in order, which narrows a singleton to the lock it was started for. */
	required?: readonly string[]
): Promise<LockResult> {
	const notes: string[] = [];
	const deadlines = lockDeadlines(timeoutMs);
	try {
		for (;;) {
			const result = attemptPidFileLock(
				pidFilePath,
				expectedCommand,
				expectedScript,
				requestedVersion,
				deadlines,
				timeoutMs,
				required,
				notes
			);
			if (typeof result !== 'number') return result;
			await delay(Math.max(retryDelay, result));
		}
	} finally {
		for (const note of notes) logger.warn(`${pidFilePath}: ${note}`);
	}
}

interface Deadlines {
	/** Past it, an unidentified holder is adopted rather than waited on. */
	identify: number;
	/** Past it, a dead pid's live keeper is no longer waited on. */
	overdue: number;
	/** Past it, the call throws: any claim or gate it waits on has been abandoned by its age well before. */
	giveUp: number;
}

function lockDeadlines(timeoutMs: number): Deadlines {
	const now = Date.now();
	return {
		identify: now + Math.min(identifyDeadlineMs, timeoutMs),
		overdue: now + timeoutMs,
		giveUp: now + 2 * timeoutMs,
	};
}

/** One look at the lock under its gate: a result, or the least wait in ms before looking again. */
function attemptPidFileLock(
	pidFilePath: string,
	expectedCommand: string,
	expectedScript: string | undefined,
	requestedVersion: number | undefined,
	deadlines: Deadlines,
	timeoutMs: number,
	required: readonly string[] | undefined,
	notes: string[]
): LockResult | number {
	const expired = Date.now() >= deadlines.identify;
	const overdue = Date.now() >= deadlines.overdue;

	// Every decision on this lock happens inside the gate, so no sibling can create a claim in the instant
	// between another thread's removal of a stale lock and its own create.
	const verdict = underGate(pidFilePath, timeoutMs, false, () => {
		let content: string | null;
		try {
			content = readFileSync(pidFilePath, 'utf-8');
		} catch {
			// No lock at all. Claiming it here rather than falling through to a bare create keeps the claim
			// inside the gate; the constrained spawn's exit handler alone removes the lock outside it, as main's does.
			content = null;
		}

		// An empty file is a lock mid-write by a spawn from before the gated commit, not a lock naming nobody;
		// taking it would put a second thread into the spawn.
		if (content !== null && content.trim() === '') {
			if (!expired) return { act: 'wait' as const };
			notes.push('reclaimed a lock that stayed empty past the identification deadline');
			content = null;
		}

		if (content !== null) {
			const held = parseLock(content);
			const decision = adjudicateLock(held, {
				expectedCommand,
				expectedScript,
				requestedVersion,
				required,
				expired,
				overdue,
				claimAgeMs: ageOf(pidFilePath),
				abandonAfterMs: timeoutMs,
				notes,
			});

			if (decision.act === 'adopt') return decision;
			if (decision.act === 'wait') return decision;

			// Signal, then unlink. Both run inside the gate, so one thread reaches them and no thread deciding to
			// adopt reads the lock between the two.
			if (decision.stop !== undefined) {
				try {
					process.kill(decision.stop);
				} catch {
					// Already exited between the identification and the signal
				}
			}
			try {
				unlinkSync(pidFilePath);
			} catch {
				// Absent is the state this wanted
			}
		}

		// Inside the gate, so this cannot lose to a sibling; 'wx' stays because a lock left behind by
		// a process outside this node is still a reason to refuse rather than overwrite.
		const fd = openSync(pidFilePath, 'wx');
		// Written before closing, so no thread deciding under the gate finds a claim without its claimant or the
		// token a keeper commits under; a keeper holding another token finds its claim taken over
		const token = `${process.pid}.${threadId}.${randomUUID()}`;
		writeSync(fd, `\n0\n${process.pid}\n${token}\n${ownStartTime() ?? ''}`);
		closeSync(fd);
		return { act: 'take' as const, token };
	});

	if (verdict?.act === 'adopt') return { pid: verdict.pid, version: verdict.version };
	// pid 0 is "the lock is yours, go spawn".
	if (verdict?.act === 'take') return { pid: 0, version: 0, token: verdict.token };

	// Every claim and gate this waits on is abandoned by its own age within timeoutMs, so waiting twice that
	// means something outside this protocol holds the lock, and the caller is told rather than handed it
	if (Date.now() >= deadlines.giveUp) {
		throw new Error(`Failed to acquire PID file lock within ${2 * timeoutMs}ms`);
	}
	return verdict?.act === 'wait' ? (verdict.pollMs ?? 0) : 0;
}

/**
 * Write `content` over the claim `token` named, inside the gate, and only while the lock still carries that token: a
 * claim taken over since is its taker's. For a caller that cannot await, the constrained spawn.
 */
export function commitPidFileLock(pidFilePath: string, token: string, content: string): 'written' | 'gone' | 'taken' {
	return withPidFileLockGate(pidFilePath, (held, stillHeld) => {
		if (held === null) return 'gone';
		if (held.token !== token) return 'taken';
		const temp = `${pidFilePath}.${token}.tmp`;
		writeFileSync(temp, content, 'utf-8');
		// A holder stalled until its gate was broken writes nothing over what its breaker decided
		if (!stillHeld()) {
			unlinkQuietly(temp);
			return 'taken';
		}
		try {
			renameSync(temp, pidFilePath);
		} catch (error) {
			unlinkQuietly(temp);
			throw error;
		}
		return 'written';
	});
}

/** Remove the claim `token` named while it still names no pid, for a caller that cannot await. */
export function releasePidFileClaim(pidFilePath: string, token: string): void {
	withPidFileLockGate(pidFilePath, (held) => {
		if (held?.token === token && held.pid <= 0) unlinkSync(pidFilePath);
	});
}

/**
 * Give a claim back while it names no pid. A keeper that committed after its thread stopped waiting is left in
 * place and returned, since removing that lock would leave its process running with none.
 */
export async function releaseUnstartedPidFileLock(
	pidFilePath: string,
	token: string
): Promise<'written' | 'gone' | 'taken' | PidLock> {
	for (;;) {
		const outcome = underGate(pidFilePath, CLAIM_TIMEOUT_MS, false, () => {
			const held = readPidLock(pidFilePath);
			if (held === null) return 'gone' as const;
			if (held.token !== token) return 'taken' as const;
			if (held.pid > 0) return held;
			unlinkSync(pidFilePath);
			return 'written' as const;
		});
		if (outcome !== null) return outcome;
		await delay(CLAIM_RETRY_MS);
	}
}

/**
 * Run `decide` on the lock as it stands while holding its gate, for a caller that cannot await. A gate still held
 * after `waitMs` is broken whatever holds it, which only an exit handler, with no time to wait, should ask for.
 */
export function withPidFileLockGate<T>(
	pidFilePath: string,
	decide: (held: PidLock | null, stillHeld: () => boolean) => T,
	waitMs = CLAIM_TIMEOUT_MS
): T {
	const deadline = Date.now() + waitMs;
	for (;;) {
		const done = underGate(pidFilePath, CLAIM_TIMEOUT_MS, Date.now() >= deadline, (stillHeld) => ({
			value: decide(readPidLock(pidFilePath), stillHeld),
		}));
		if (done !== null) return done.value;
		Atomics.wait(PAUSE, 0, 0, CLAIM_RETRY_MS);
	}
}

/** withPidFileLockGate that gives up rather than breaking a live holder's gate: null when it was not free in `waitMs`. */
export function tryPidFileLockGate<T>(
	pidFilePath: string,
	decide: (held: PidLock | null) => T,
	waitMs: number
): T | null {
	const deadline = Date.now() + waitMs;
	for (;;) {
		const done = underGate(pidFilePath, CLAIM_TIMEOUT_MS, false, () => ({ value: decide(readPidLock(pidFilePath)) }));
		if (done !== null) return done.value;
		if (Date.now() >= deadline) return null;
		Atomics.wait(PAUSE, 0, 0, CLAIM_RETRY_MS);
	}
}
