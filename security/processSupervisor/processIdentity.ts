// Positive identification of the process behind a pid, as distinct from whether something holds it.
// "Not ours" and "cannot tell" are different answers, and neither authorizes a signal where a platform can identify.
import { execFileSync } from 'node:child_process';
import { readFileSync, readlinkSync, realpathSync } from 'node:fs';
import { basename, isAbsolute, join } from 'node:path';

import { PACKAGE_ROOT } from '../../utility/packageUtils.js';
import { commandLineEnv, inspect, startTimeEnv } from './sidecarKeeper.js';

/** The parent every scope.processes sidecar runs under on Linux and darwin, run by path as the reaper is. */
export const KEEPER_SCRIPT = join(PACKAGE_ROOT, 'security', 'processSupervisor', 'sidecarKeeper.js');

export type ProcessIdentification =
	// This pid is running that command; a caller may act on it
	| 'match'
	// This pid is not running that command: it runs nothing, runs another program, or on Linux runs as another user
	| 'differs'
	// Not established; where the platform can identify, a caller must not signal it either
	| 'unknown';

/** How long one `ps` may take. */
const PS_TIMEOUT_MS = 2000;
let psTimeoutMs = PS_TIMEOUT_MS;

// Test-only: a suite that makes `ps` hang shortens the timeout. No argument restores the shipped value, returned.
export function _setPsTimeoutForTests(ms: number = PS_TIMEOUT_MS): number {
	psTimeoutMs = ms;
	return psTimeoutMs;
}
/** Set while one identification runs: once a `ps` in it has timed out, its later reads fail at once. */
let identifying: { psTimedOut: boolean } | null = null;

/**
 * `ps -o <fields>` for one pid, trimmed. Inside one identification a timeout makes every later read in it throw at
 * once, so a hung `ps` costs that identification one timeout; the next asks `ps` afresh.
 */
function ps(pid: number, fields: string, env?: NodeJS.ProcessEnv): string {
	if (identifying?.psTimedOut) throw new Error('ps timed out earlier in this identification');
	try {
		return execFileSync('ps', ['-p', String(pid), '-o', fields], {
			encoding: 'utf-8',
			timeout: psTimeoutMs,
			stdio: ['ignore', 'pipe', 'ignore'],
			...(env ? { env } : {}),
		}).trim();
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === 'ETIMEDOUT' && identifying) identifying.psTimedOut = true;
		throw error;
	}
}

/** Run one identification; a nested one shares the outer's record of a timed-out `ps`. */
function identification<T>(identify: () => T): T {
	if (identifying) return identify();
	identifying = { psTimedOut: false };
	try {
		return identify();
	} finally {
		identifying = null;
	}
}

/**
 * The state field of /proc/<pid>/stat, or null when the content does not parse. The comm field is
 * parenthesised and may itself contain spaces and parens, so the state is the token after the LAST ')'.
 */
export function parseProcStatState(stat: string): string | null {
	const commEnd = stat.lastIndexOf(')');
	if (commEnd === -1) return null;
	const [state] = stat
		.slice(commEnd + 1)
		.trim()
		.split(/\s+/, 1);
	return state || null;
}

/** A zombie still holds its pid but runs nothing and never will again; kill(pid, 0) cannot see that. */
function isZombie(pid: number): boolean {
	try {
		if (process.platform === 'linux') {
			return parseProcStatState(readFileSync(`/proc/${pid}/stat`, 'utf-8')) === 'Z';
		}
		if (process.platform === 'darwin') return ps(pid, 'state=').startsWith('Z');
	} catch {
		// An unreadable state says nothing; liveness has already been answered by kill(pid, 0)
	}
	return false;
}

/**
 * Whether anything holds this pid, a dead-but-unreaped zombie included: one syscall, no state read.
 * Only a caller that polls often enough for the state read to cost it should ask this instead of liveness.
 */
export function pidIsHeld(pid: number): boolean {
	// Non-positive values are process-group selectors to kill(2), not pids, so asking would answer for the group
	if (!Number.isInteger(pid) || pid <= 0) return false;
	try {
		process.kill(pid, 0);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== 'EPERM') return false;
	}
	return true;
}

/**
 * Checks whether some process holds this pid AND still runs: a dead-but-unreaped zombie answers
 * kill(pid, 0) yet is not alive. EPERM still means it exists, owned by another user.
 */
export function isProcessAlive(pid: number): boolean {
	return pidIsHeld(pid) && !isZombie(pid);
}

/**
 * On Linux a sidecar runs as Harper's own user, so a pid that refuses kill(pid, 0) with EPERM, or whose
 * executable link refuses the read with EACCES, belongs to another user and is not the one asked about.
 */
function isAnotherUsersProcess(pid: number): boolean {
	if (process.platform !== 'linux') return false;
	try {
		process.kill(pid, 0);
	} catch (error) {
		return (error as NodeJS.ErrnoException).code === 'EPERM';
	}
	try {
		readlinkSync(`/proc/${pid}/exe`);
	} catch (error) {
		return (error as NodeJS.ErrnoException).code === 'EACCES';
	}
	return false;
}

/**
 * Reports the executable behind a pid as the platform describes it, or null when it cannot be established.
 * Null covers unreadable platforms, another user's process on Linux when not root, and a pid that exited while being asked.
 */
export function executableOf(pid: number): string | null {
	if (!isProcessAlive(pid)) return null;
	try {
		if (process.platform === 'linux') {
			// Kernel-set, so argv cannot rewrite it; a replaced binary's "<path> (deleted)" does not resolve, so null
			return realpathSync(readlinkSync(`/proc/${pid}/exe`));
		}
		if (process.platform === 'darwin') {
			// `comm` is the path as invoked: absolute for a process started by path, bare for one found on PATH
			const reported = ps(pid, 'comm=', commandLineEnv());
			return reported === '' ? null : reported;
		}
		// Windows and anything else: cannot tell, which a caller must not read as "not ours"
		return null;
	} catch {
		return null;
	}
}

/**
 * Reports the argument vector behind a pid, or null when it cannot be read. argv is process-writable
 * where /proc/<pid>/exe is kernel-set: confidence against pid reuse and stale locks, not proof against a forger.
 */
export function argumentsOf(pid: number): string[] | null {
	if (!isProcessAlive(pid)) return null;
	try {
		if (process.platform === 'linux') {
			// NUL-separated with a trailing NUL; a kernel thread has none at all, which reads as unknown
			const argv = readFileSync(`/proc/${pid}/cmdline`, 'utf-8').split('\0').filter(Boolean);
			return argv.length > 0 ? argv : null;
		}
		if (process.platform === 'darwin') {
			// `args` is the vector re-joined with spaces, so an argument containing one cannot be recovered
			const reported = ps(pid, 'args=', commandLineEnv());
			return reported === '' ? null : reported.split(/\s+/);
		}
		// Windows and anything else: cannot tell, which a caller must not read as "not ours"
		return null;
	} catch {
		return null;
	}
}

/** The executable half of the answer: only a full-path comparison decides, bare names yield 'unknown'. */
function identifyExecutable(pid: number, command: string): ProcessIdentification {
	const actual = executableOf(pid);
	if (actual === null) return 'unknown';

	let expected: string;
	try {
		expected = realpathSync(command);
	} catch {
		// The expected command is not on disk (or is a bare PATH name); that says nothing about the process
		return 'unknown';
	}

	if (isAbsolute(actual)) {
		try {
			return realpathSync(actual) === expected ? 'match' : 'differs';
		} catch {
			// darwin reports the path as invoked, which may have been removed since; compare it as written
			return actual === expected ? 'match' : 'differs';
		}
	}
	return basename(actual) === basename(expected) ? 'unknown' : 'differs';
}

/** The script half, on the executable's rules: full-path agreement matches, name-only cannot tell. */
function identifyScript(pid: number, script: string): ProcessIdentification {
	const argv = argumentsOf(pid);
	if (argv === null) return 'unknown';
	let expected: string;
	try {
		expected = realpathSync(script);
	} catch {
		// The expected script is not on disk; that says nothing about the process
		return 'unknown';
	}

	let sameName = false;
	// argv[0] is the interpreter, which identifyExecutable has already answered for
	for (const argument of argv.slice(1)) {
		if (argument === expected) return 'match';
		try {
			// A relative argument resolves against THIS process's cwd, so disagreement here is not evidence of anything
			if (realpathSync(argument) === expected) return 'match';
		} catch {
			// Not a readable path; it can still agree by name below
		}
		if (basename(argument) === basename(expected)) sameName = true;
	}
	return sameName ? 'unknown' : 'differs';
}

/**
 * Determines whether `pid` is running `command`, keeping "cannot tell" distinct from "not ours". Pass
 * `script` for an interpreter: its executable is the same binary for every script it is given.
 */
export function identifyProcess(
	pid: number,
	command: string,
	script?: string,
	/** Arguments that must appear in order, such as the lock a singleton was started for. */
	required?: readonly string[]
): ProcessIdentification {
	return identification(() => identifyRunning(pid, command, script, required));
}

function identifyRunning(
	pid: number,
	command: string,
	script: string | undefined,
	required: readonly string[] | undefined
): ProcessIdentification {
	if (!command) return 'unknown';
	// A dead or zombie pid runs nothing, so it is not the expected command. A fourth answer would read
	// as neither 'differs' nor 'unknown' at the call sites, where anything else means "adopt it".
	if (!isProcessAlive(pid)) return 'differs';
	// Before either half, since another user's argv stays readable and could otherwise agree
	if (isAnotherUsersProcess(pid)) return 'differs';
	const executable = identifyExecutable(pid, command);
	// A keeper runs as node and carries its sidecar's arguments, and it is never the sidecar
	if (executable !== 'differs' && isKeeperProcess(pid, command)) return 'differs';
	if (!script) return executable;
	if (executable === 'differs') return 'differs';

	// Both halves must agree to authorize a signal: either half reading 'differs' is decisive, and an
	// argv this platform will not surrender leaves the whole answer unknown rather than adopting on the binary
	const named = identifyScript(pid, script);
	if (named === 'differs') return 'differs';
	if (required?.length && !carriesArguments(pid, required)) return 'differs';
	return named === 'unknown' || executable === 'unknown' ? 'unknown' : 'match';
}

/** Whether the argument vector holds `required` in order; unreadable reads as carrying it, which leaves "cannot tell". */
function carriesArguments(pid: number, required: readonly string[]): boolean {
	const argv = argumentsOf(pid);
	return argv === null || ` ${argv.join(' ')} `.includes(` ${required.join(' ')} `);
}

/** A launcher or keeper of sidecarKeeper.js, by its argv; asked of a node command alone, since a keeper runs as node. */
function isKeeperProcess(pid: number, command: string): boolean {
	if (basename(command) !== 'node' && basename(command) !== basename(process.execPath)) return false;
	const joined = argumentsOf(pid)?.join(' ') ?? '';
	return joined.includes('/sidecarKeeper.js --keep ') || joined.includes('/sidecarKeeper.js --launch ');
}

/** The keeper's `ps` for its start-time read, in the keeper's environment, inside this module's one-timeout budget. */
function psAsKeeper(pid: number, fields: string): string {
	return ps(pid, fields, startTimeEnv());
}

/** When a pid started, comparable only for equality, or null when it is gone or cannot be read. An exec keeps it. */
export function startedAt(pid: number): string | null {
	// The keeper's own read, since the keeper records the start time a thread compares
	return inspect(pid, psAsKeeper).started;
}

export function parentOf(pid: number): number | null {
	return inspect(pid, psAsKeeper).ppid;
}

/** Whether `expected` leads a pid's argument vector; darwin's `ps` joins it, so there joined text is compared. */
function argvLeads(pid: number, expected: readonly string[]): ProcessIdentification {
	if (!isProcessAlive(pid)) return 'differs';
	const actual = argumentsOf(pid);
	if (actual === null || expected.length === 0) return 'unknown';
	if (process.platform === 'darwin') {
		const joined = actual.join(' ');
		const want = expected.join(' ');
		return joined === want || joined.startsWith(`${want} `) ? 'match' : 'differs';
	}
	return expected.every((argument, index) => actual[index] === argument) ? 'match' : 'differs';
}

/** What a keeper wrote beside the pid it committed: itself, the command line it runs, and when the pid started. */
export interface KeptRecord {
	keeper?: number;
	keeperArgv?: readonly string[];
	started?: string;
}

/** Whether a pid is the keeper whose command line leads with `keeperArgv`, which names its lock and its token. */
export function identifyKeeper(keeper: number, keeperArgv: readonly string[]): ProcessIdentification {
	if (!Number.isInteger(keeper) || keeper <= 1) return 'differs';
	return argvLeads(keeper, keeperArgv);
}

/**
 * identifyProcess, except that a recorded start time decides: equal is that process whatever it now runs, and a
 * readable other one is a reused pid. Without one, a pid whose parent is the lock's keeper is vouched for by it.
 */
export function identifyKept(
	pid: number,
	command: string,
	script: string | undefined,
	kept: KeptRecord | undefined,
	required?: readonly string[]
): ProcessIdentification {
	return identification(() => {
		if (!isProcessAlive(pid)) return 'differs';
		let unread = false;
		if (kept?.started) {
			const started = startedAt(pid);
			if (started === kept.started) return 'match';
			if (started !== null) return 'differs';
			// A pid gone since the liveness read is gone, not unreadable
			if (!pidIsHeld(pid)) return 'differs';
			unread = true;
		}
		const verdict = vouchedFor(pid, identifyRunning(pid, command, script, required), kept);
		// A start time recorded and now unreadable says nothing either way, and a kept process that exec'd reads as another
		return unread && verdict === 'differs' ? 'unknown' : verdict;
	});
}

/** A pid whose parent is the keeper its lock records takes that keeper's identity; pid 1 vouches for nothing. */
function vouchedFor(pid: number, verdict: ProcessIdentification, kept: KeptRecord | undefined): ProcessIdentification {
	if (verdict === 'match' || kept?.keeper === undefined || !kept.keeperArgv?.length) return verdict;
	if (kept.keeper <= 1 || parentOf(pid) !== kept.keeper) return verdict;
	// A parent that cannot be identified leaves its child unidentified, never "not ours"
	const vouched = identifyKeeper(kept.keeper, kept.keeperArgv);
	return vouched === 'differs' ? verdict : vouched;
}

/**
 * Reports whether this module identifies what a pid runs on this platform. Linux's executable answer
 * is kernel-supplied; darwin's is argv, as is the script half on both; elsewhere this module reads neither.
 */
export function platformCanIdentifyProcesses(): boolean {
	return process.platform === 'linux' || process.platform === 'darwin';
}
