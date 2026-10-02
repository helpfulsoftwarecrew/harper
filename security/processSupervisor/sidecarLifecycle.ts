// Lifecycle for the child processes a component owns: write configs atomically, spawn through the
// PID lock, keep the process alive, and verify it works.
import { accessSync, constants, existsSync, mkdirSync, renameSync, writeFileSync } from 'node:fs';
import type { ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import { dirname, isAbsolute, join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { threadId } from 'node:worker_threads';

import * as env from '../../utility/environment/environmentManager.ts';
import { CONFIG_PARAMS, HDB_PID_FILE } from '../../utility/hdbTerms.ts';
import { type Logger } from '../../utility/logging/logger.ts';
import { PACKAGE_ROOT } from '../../utility/packageUtils.js';
import { ExistingProcessWrapper } from './adoptionWrapper.ts';
import { KEEPER_SCRIPT, identifyKeeper, identifyKept, isProcessAlive, startedAt } from './processIdentity.ts';
import { readPidLock, releaseUnstartedPidFileLock, type PidLock } from './pidFileLock.ts';
import { claimDeadPidFileLock } from './pidLockClaim.ts';
import { writeSidecarTarget } from './sidecarRegistry.ts';
// The keeper writes the record and decides what a deliberate stop is, so its reader and its rule are the ones used here
import { STOP_SIGNALS, isDeliberate, readRecord } from './sidecarKeeper.js';

/** How long a spawn given no pid is waited on for the 'error' that says why. */
const SPAWN_ERROR_WAIT_MS = 1000;
/** Deaths one thread will restart through before it stops and waits for the component to reload. */
const RESPAWN_MAX_ATTEMPTS = 5;
/** The first restart's wait, doubled per attempt and clamped, so a binary that cannot start is not a spin. */
const RESPAWN_BASE_MS = 1000;
const RESPAWN_CAP_MS = 30_000;
/** How long a replacement reaper must survive before its death counts as a fresh incident rather than a
 * continuing failure. Longer than the whole backoff ladder, so a genuine crash loop still exhausts it. */
const REAPER_STABLE_MS = 60_000;
/** How often a thread that stood down looks for the replacement the claim winner is starting. */
const REJOIN_POLL_MS = 250;
/** How much longer than that restart's backoff it looks before reporting that nothing is running. */
const REJOIN_GRACE_MS = 15_000;
/** How long the reaper waits for a `harper restart` replacement before stopping the sidecars. */
const REAPER_RESTART_GRACE_MS = 8000;
/** A lock and a record read each, so a thread waiting on its keeper polls without forking anything. */
const KEEPER_WATCH_MS = 10;
/** How often a thread waiting on a keeper's restart asks what the committed pid runs, which forks `ps` on darwin. */
const KEEPER_IDENTIFY_MS = 50;
/** How often a thread waiting on a keeper checks that the keeper is still there to write what it waits for. */
const KEEPER_ALIVE_MS = 250;
/** Two node starts, a start-time read and the commit through the gate, before a start gives its claim back. */
const KEEPER_START_MS = 15_000;
/** How long a death waits for its keeper's record while the keeper lives: the longest the lock's gate is held. */
const KEEPER_RECORD_WAIT_MS = 30_000;

const SHIPPED_TIMING = {
	respawnBaseMs: RESPAWN_BASE_MS,
	rejoinPollMs: REJOIN_POLL_MS,
	rejoinGraceMs: REJOIN_GRACE_MS,
	keeperStartMs: KEEPER_START_MS,
};
let timing = { ...SHIPPED_TIMING };

// Test-only: a suite shortens the backoff, the rejoin window and the keeper's start rather than sitting out real
// seconds. No argument restores the shipped values, which are returned, so a test can pin what ships.
export function _setTimingForTests(overrides: Partial<typeof SHIPPED_TIMING> = {}): Readonly<typeof SHIPPED_TIMING> {
	timing = { ...SHIPPED_TIMING, ...overrides };
	return { ...timing };
}

// A component that supervises its own sidecars may run its own reaper in this pid directory, and a shared
// singleton lock name would leave one reaper's targets unwatched
export const REAPER_NAME = 'harper-sidecar-reaper';

/**
 * Run by path, under a keeper or forked where none runs, so the type checker cannot follow this literal: exported so
 * a test asserts the value used. A stale path shows only as a second reaper starting beside the first.
 */
export const REAPER_SCRIPT = join(PACKAGE_ROOT, 'security', 'processSupervisor', 'sidecarReaper.js');

import {
	child_processConstrained,
	errorMessage,
	lockPathFor,
	pidDirectory,
	spawnKept,
} from './constrainedChildProcess.ts';
import type { KeptSpawn, KeptStart, LockedFork, LockedSpawn, SpawnedChild } from './constrainedChildProcess.ts';

export type { SpawnedChild, LockedSpawn, LockedFork, KeptSpawn } from './constrainedChildProcess.ts';

/** The keeper holding a process: its token on the lock, its pid and command line, and when this thread began watching. */
interface Kept {
	token: string;
	keeper: number;
	keeperArgv: readonly string[];
	since: number;
}

/** What sidecarKeeper.js writes to `<name>.pid.exit` for each death, and for a start that never ran. */
interface KeeperRecord {
	token: string;
	keeper: number;
	pid: number;
	code: number | null;
	signal: NodeJS.Signals | null;
	outcome: 'released' | 'restarting' | 'gave-up' | 'gone' | 'taken' | 'failed';
	restarts: number;
	waitMs: number;
	at: number;
	released: boolean;
	error?: string;
}

function readKeeperRecord(lockPath: string): KeeperRecord | null {
	return readRecord(lockPath) as KeeperRecord | null;
}

/** The command line a keeper records for its lock and token, rebuilt for one that ended before a thread saw it. */
export function keeperArgvFor(lockPath: string, token: string): string[] {
	return [process.execPath, KEEPER_SCRIPT, '--keep', '--lock', lockPath, '--token', token];
}

/** The keeper a lock records beside the pid it names, or null for a lock Harper's own spawn wrote. */
function keptBy(lock: PidLock | null): Kept | null {
	if (!lock || lock.keeper === undefined || !lock.token || !lock.keeperArgv?.length) return null;
	return { token: lock.token, keeper: lock.keeper, keeperArgv: lock.keeperArgv, since: Date.now() };
}

type KeeperStarted =
	| { pid: number; keeper: number; keeperArgv: readonly string[]; started?: string; ended: boolean }
	| { error: string; takenOver?: boolean; gaveBack?: boolean };

/** Wait for the keeper to commit the pid it started under `token`, or to say why it could not. */
async function awaitKeeper(path: string, token: string, launcher: ChildProcess): Promise<KeeperStarted> {
	let launcherExit: string | null = null;
	const reaped = new Promise<void>((resolve) => {
		launcher.once('exit', (code, signal) => {
			launcherExit = signal ? `signal ${signal}` : `exit code ${code}`;
			resolve();
		});
		// Attached so a launcher that could not start ends the wait rather than the worker thread
		launcher.once('error', (error) => {
			launcherExit ??= error.message;
			resolve();
		});
	});
	// Reaped before this returns, so a thread ended right after the start leaves no zombie launcher
	const reapLauncher = () => Promise.race([reaped, delay(1000, undefined, { ref: false })]);
	const startMs = timing.keeperStartMs;
	const deadline = Date.now() + startMs;
	for (;;) {
		const held = readPidLock(path);
		const record = readKeeperRecord(path);
		if (held?.token === token && held.pid > 0 && held.keeper !== undefined) {
			await reapLauncher();
			return {
				pid: held.pid,
				keeper: held.keeper,
				keeperArgv: held.keeperArgv ?? [],
				started: held.started,
				ended: false,
			};
		}
		if (record?.token === token && record.outcome === 'failed') {
			// The keeper gives the claim back itself; one it could not is given back here
			if (record.released !== true && held?.token === token) await releaseUnstartedPidFileLock(path, token);
			return { error: record.error ?? 'its keeper gave no reason' };
		}
		// Ended between two looks: its keeper writes the record before the lock goes, so it is here when the lock is not
		if (record?.token === token && record.pid > 0) {
			await reapLauncher();
			return { pid: record.pid, keeper: record.keeper, keeperArgv: keeperArgvFor(path, token), ended: true };
		}
		if (held?.token !== token)
			return { error: 'its claim was taken over before its keeper named a pid', takenOver: true };
		const gaveUp =
			launcherExit !== null && launcherExit !== 'exit code 0'
				? `the keeper's launcher ended with ${launcherExit}`
				: Date.now() >= deadline
					? `its keeper named no pid within ${startMs}ms`
					: null;
		if (gaveUp !== null) {
			// Given back only while it names no pid: a keeper that committed since the look above is joined instead
			const given = await releaseUnstartedPidFileLock(path, token);
			if (typeof given === 'string' || given.keeper === undefined)
				return { error: gaveUp, gaveBack: given === 'written' };
			await reapLauncher();
			return {
				pid: given.pid,
				keeper: given.keeper,
				keeperArgv: given.keeperArgv ?? [],
				started: given.started,
				ended: false,
			};
		}
		await delay(KEEPER_WATCH_MS);
	}
}

/** The keeper's record of the death of `pid`, or null once the keeper is gone or the wait passes without one. */
async function awaitKeeperRecord(lockPath: string, kept: Kept, pid: number): Promise<KeeperRecord | null> {
	// A crash loop overwrites the record of the death this thread saw with a later one, which still answers it
	const matches = (record: KeeperRecord | null): record is KeeperRecord =>
		record !== null && record.token === kept.token && (record.pid === pid || record.at >= kept.since);
	const deadline = Date.now() + KEEPER_RECORD_WAIT_MS;
	let checked = Date.now();
	for (;;) {
		const record = readKeeperRecord(lockPath);
		if (matches(record)) return record;
		if (Date.now() >= deadline) return null;
		if (Date.now() - checked >= KEEPER_ALIVE_MS) {
			checked = Date.now();
			// Read once more after the keeper is found gone: it may have written on its way out
			if (identifyKeeper(kept.keeper, kept.keeperArgv) === 'differs') {
				const last = readKeeperRecord(lockPath);
				return matches(last) ? last : null;
			}
		}
		await delay(KEEPER_WATCH_MS, undefined, { ref: false });
	}
}

export interface SidecarDescriptor {
	/** Spawn name, which is also the PID-lock filename under <rootPath>/pids. */
	name: string;
	/** The binary to run; `applications.allowedSpawnCommands` still gates it, no new config. */
	command: string;
	args?: readonly string[];
	/** Set when `command` is an interpreter: every process running that binary identifies alike without it. */
	script?: string;
	/** How messages name it. Defaults to `name`. */
	title?: string;
	/** Inputs hashed into the spawn version; a changed fingerprint replaces the running process. */
	fingerprint?: readonly unknown[];
	/** Files written via write-then-rename, so a rereading process never sees a torn file. */
	configFiles?: Readonly<Record<string, string>>;
	/** Appended to the non-zero-exit report, for the caller's domain knowledge ("port in use" and the like). */
	exitHint?: string;
	/** Set false to skip the detached reaper; without it the process outlives an ungracefully-killed node. */
	reaper?: boolean;
	/**
	 * Proves the process does its job, awaited after the spawn. `reason` lets a `'refuted'` retake inside a
	 * status read spend less than a boot proof, which may wait for a process that has bound nothing yet.
	 */
	verify?: (
		state: SidecarState,
		context?: { reason: 'restarted' | 'untaken' | 'refuted' }
	) => Promise<{ ok: boolean; detail?: string }>;
}

export interface SidecarState {
	name: string;
	title: string;
	command: string;
	version?: number;
	started: boolean;
	/** True when this thread lost the PID-lock race and joined an existing process. */
	adopted?: boolean;
	pid?: number | undefined;
	/** Set when the process is seen to die: the owner's exit event, or a joiner's liveness poll. */
	exited?: boolean | undefined;
	error?: string | undefined;
	/** How many times the process has been restarted after a death: by its keeper where it has one, else by this thread. */
	restarts?: number;
	/** Exit code of the last death, from its keeper's record or a child this thread spawned; unset where neither exists. */
	code?: number | undefined;
	/** Signal that ended the last death, from the same two sources. */
	signal?: string | undefined;
	/** A restart can replace the pid this was taken against; compare it with `pid` before trusting the verdict. */
	verified?: boolean;
	verifyDetail?: string | undefined;
	/** The pid the verdict above describes, stamped before the proof runs. Null when there was no pid. */
	verifiedPid?: number | null;
	/** When the verdict was last taken, so a refusal can be re-asked without every reader paying a probe. */
	verifiedAt?: number;
}

/** Fingerprint of what forces replacement of a running process; a number inside 2^31 because the lock parseInt()s it. */
export function fingerprintVersion(...parts: unknown[]): number {
	return createHash('sha256').update(parts.map(String).join('\0')).digest().readUInt32BE(0) >>> 1;
}

/** The allowlist hint, for the refusal it answers alone: a PID lock that could not be taken is not one. */
function allowlistHint(message: string, command: string): string {
	return /is not allowed/.test(message)
		? `. Add this exact path to applications.allowedSpawnCommands and restart Harper: ${command}`
		: '';
}

/**
 * The attempt number a reaper's replacement runs under, or null when the budget is spent. A reaper that ran
 * past REAPER_STABLE_MS starts a fresh count, so the budget bounds a crash loop, not the node's lifetime.
 *
 * @param attempt The attempt the incarnation that just died was running under.
 * @param livedMs How long it ran before dying.
 */
export function nextReaperAttempt(attempt: number, livedMs: number): number | null {
	const next = livedMs > REAPER_STABLE_MS ? 0 : attempt + 1;
	return next > RESPAWN_MAX_ATTEMPTS ? null : next;
}

/** One schedule for both paths: the winner's wait before a restart, and how long the others wait for it. */
function backoffMs(attempt: number): number {
	return Math.min(timing.respawnBaseMs * 2 ** attempt, RESPAWN_CAP_MS);
}

/** Refuse a binary the spawn cannot start; only absolute paths are checkable, bare allowlist names pass through. */
function preflightBinary(title: string, command: string): void {
	if (!isAbsolute(command)) return;
	if (command.includes(' ')) {
		// The allowlist is matched with command.split(' ')[0], so no entry can ever match a spaced path
		throw new Error(
			`the ${title} binary path contains a space, which no allowedSpawnCommands entry can match: ${command}`
		);
	}
	if (!existsSync(command)) throw new Error(`the ${title} binary is missing at ${command}`);
	accessSync(command, constants.X_OK);
}

/**
 * The `scope.processes` surface: starts a component's sidecar processes through the PID lock, one of each name per node
 * however many worker threads call it, each under a keeper on Linux and darwin.
 */
export class SidecarProcesses {
	#logger: Logger;
	#spawn: LockedSpawn | undefined;
	#fork: LockedFork | undefined;
	#keep: KeptSpawn | null;
	#states: SidecarState[] = [];
	#reaper: SidecarState | undefined;
	/** The reaper as a descriptor for the keeper's path; the one descriptor spawned as a fork, by identity. */
	#reaperDescriptor: SidecarDescriptor | undefined;
	#reaperStarting: Promise<void> | undefined;

	/** `keep` null starts each process as this thread's own child, which is the path on Windows, where no keeper runs. */
	constructor(logger: Logger, spawn?: LockedSpawn, fork?: LockedFork, keep?: KeptSpawn | null) {
		this.#logger = logger;
		this.#spawn = spawn;
		this.#fork = fork;
		this.#keep = keep !== undefined ? keep : process.platform === 'win32' ? null : spawnKept;
	}

	/** One state per started descriptor, in start order. */
	get states(): readonly SidecarState[] {
		return this.#states;
	}

	/** The detached reaper's state, once a start has launched (or joined) it. */
	get reaper(): SidecarState | undefined {
		return this.#reaper;
	}

	/** Write configs, spawn through the lock, ensure the reaper, then verify. */
	async start(descriptor: SidecarDescriptor): Promise<SidecarState> {
		if (!descriptor?.name || !descriptor.command) {
			throw new TypeError('a sidecar descriptor requires both a name (the PID-lock name) and a command');
		}
		// The name is the lock's file name, so another directory or spelling would name another lock or the reaper's
		if (!/^[\w.-]+$/.test(descriptor.name) || descriptor.name === '.' || descriptor.name === '..') {
			throw new TypeError(`a sidecar name is one file name of letters, digits, '.', '_' and '-': ${descriptor.name}`);
		}
		// Case folds on darwin's and Windows' file systems, and a start under the reaper's lock would stop the reaper
		if (descriptor.name.toLowerCase() === REAPER_NAME) {
			throw new TypeError(`${REAPER_NAME} is the name of this node's reaper`);
		}
		const title = descriptor.title ?? descriptor.name;
		const version = descriptor.fingerprint ? fingerprintVersion(...descriptor.fingerprint) : undefined;
		const pidDir = pidDirectory();
		mkdirSync(pidDir, { recursive: true });
		// The same allowlisted, PID-locked spawn a component receives
		this.#spawn ??= child_processConstrained.spawn as LockedSpawn;
		this.#fork ??= child_processConstrained.fork as LockedFork;

		// Every thread writes, and the rename keeps concurrent writers and rereading processes safe
		if (descriptor.configFiles) this.#writeConfigFiles(descriptor.configFiles);

		const state: SidecarState = { name: descriptor.name, title, command: descriptor.command, started: false };
		if (version !== undefined) state.version = version;
		this.#states.push(state);
		// The one call that does not verify from inside the spawn: the reaper has to be launched between the
		// two, and this is the only path that can await the verdict rather than leave it running.
		await this.#spawnProcess(descriptor, version, state, 0, false);

		// Before verify, which may wait 30s: a node killed inside that window must not orphan the child
		if (state.started && descriptor.reaper !== false) await this.#ensureReaper(pidDir);

		if (descriptor.verify && state.started) await this.#verify(descriptor, state);
		return state;
	}

	#writeConfigFiles(configFiles: Readonly<Record<string, string>>): void {
		for (const [target, contents] of Object.entries(configFiles)) {
			try {
				mkdirSync(dirname(target), { recursive: true });
				const temp = `${target}.${process.pid}.${threadId}.tmp`;
				writeFileSync(temp, contents, 'utf-8');
				renameSync(temp, target);
			} catch (error) {
				this.#logger.error?.(`could not write ${target}: ${errorMessage(error)}`);
			}
		}
	}

	async #spawnProcess(
		descriptor: SidecarDescriptor,
		version: number | undefined,
		state: SidecarState,
		attempt: number,
		/** Whether this call owns the verification. False only for the first start, which awaits it itself. */
		verifyAfterStart = true
	): Promise<void> {
		const title = state.title;
		state.restarts = attempt;
		this.#clearDeath(state);
		// And the incarnation itself, so a restart that cannot spawn reads as stopped rather than as the pid that died
		state.started = false;
		state.pid = undefined;

		try {
			// The reaper runs this node binary, which a spawn allows as it allows the constrained fork
			if (descriptor !== this.#reaperDescriptor) preflightBinary(title, descriptor.command);
		} catch (error) {
			this.#refuse(state, error, (why) => `cannot start the ${title}: ${why}`);
			return;
		}

		if (this.#keep) return this.#startKept(descriptor, version, state, attempt, verifyAfterStart);

		let child: SpawnedChild;
		try {
			child = this.#spawn(descriptor.command, [...(descriptor.args ?? [])], {
				name: descriptor.name,
				version,
				script: descriptor.script,
				// Never piped: a pipe ties the child to the winning thread, which `harper dev` recycles on every save
				stdio: ['ignore', 'ignore', 'ignore'],
				env: process.env,
			});
		} catch (error) {
			this.#refuse(
				state,
				error,
				(why) => `refused to spawn the ${title}: ${why}${allowlistHint(why, descriptor.command)}`
			);
			return;
		}

		// Attached before anything else: an unhandled 'error' on a ChildProcess kills the worker thread
		const failed = new Promise<Error>((resolve) => child.once('error', resolve));
		child.on('error', (error: NodeJS.ErrnoException) => {
			this.#logger.error?.(`the ${title} failed to execute: ${error.message}`);
		});
		// A spawn that could not exec has no pid and emits 'error' rather than 'exit', so nothing would ever correct it
		if (Array.isArray(child.spawnargs) && typeof child.pid !== 'number') {
			const error = await Promise.race([failed, delay(SPAWN_ERROR_WAIT_MS, null, { ref: false })]);
			state.error = error ? errorMessage(error) : 'it was given no pid';
			this.#logger.error?.(`the ${title} failed to start: ${state.error}`);
			return;
		}

		state.pid = child.pid;
		state.started = true;

		if (typeof child.pid === 'number') this.#recordTarget(descriptor, state, child.pid);

		// The adoption wrapper lacks `spawnargs`; stdout is not a tell, since an ignored-stdio winner also has none
		const adopted = !Array.isArray(child.spawnargs);
		state.adopted = adopted;
		if (adopted) {
			this.#logger.info?.(
				`the ${title} is already running on this node (pid ${child.pid}); this thread joined it instead of starting a second one`
			);
			// unref stops the wrapper's poll from holding the event loop open, never from polling: it is
			// this thread's only notice that the process it joined has died
			child.unref();
		} else {
			this.#logger.info?.(
				`started the ${title} (pid ${child.pid}): ${descriptor.command} ${(descriptor.args ?? []).join(' ')}`
			);
		}

		child.on('exit', (code: number | null, signal: NodeJS.Signals | null) => {
			state.exited = true;
			// For a status surface: `exited` alone cannot tell a SIGKILL from a clean stop
			state.code = code ?? undefined;
			state.signal = signal ?? undefined;
			if (adopted) {
				this.#recoverOwnerlessDeath(descriptor, version, state, child.pid, attempt);
				return;
			}
			if (signal) {
				// A stop signal is someone shutting it down; anything else is a crash nothing else recovers from
				if (STOP_SIGNALS.includes(signal)) {
					this.#reportNotRunning(state);
					this.#logger.warn?.(`the ${title} was terminated by ${signal}`);
				} else {
					this.#logger.error?.(`the ${title} was terminated by ${signal}; that is a crash or an OOM kill`);
					this.#respawn(descriptor, version, state, attempt, `signal ${signal}`);
				}
				return;
			}
			if (code === 0) {
				this.#reportNotRunning(state);
				this.#logger.info?.(`the ${title} exited cleanly`);
				return;
			}
			this.#logger.error?.(
				`the ${title} exited with code ${code}; its PID lock is removed, so the next start will try again${descriptor.exitHint ? `. ${descriptor.exitHint}` : ''}`
			);
			this.#respawn(descriptor, version, state, attempt, `exit code ${code}`);
		});

		// Retaken here because only this thread knows a restart replaced the pid. Not awaited: a verify may
		// wait 30 seconds, and #verify never rejects.
		if (verifyAfterStart && descriptor.verify && state.started) void this.#verify(descriptor, state);
	}

	/**
	 * The descriptor is what outlives this thread: the main process stops the sidecar from it at graceful exit,
	 * and the detached reaper reads it after an ungraceful one.
	 */
	#recordTarget(
		descriptor: SidecarDescriptor,
		state: SidecarState,
		pid: number,
		started?: string,
		readStart = true
	): void {
		// The reaper stops what is recorded, and it is not one of those
		if (descriptor === this.#reaperDescriptor) return;
		const since = started ?? (readStart ? startedAt(pid) : null);
		try {
			writeSidecarTarget(pidDirectory(), {
				name: descriptor.name,
				pidFile: lockPathFor(descriptor.name),
				pid,
				command: descriptor.command,
				script: descriptor.script,
				...(since ? { started: since } : {}),
			});
		} catch (error) {
			this.#logger.warn?.(`could not record the ${state.title} for shutdown (${errorMessage(error)})`);
		}
	}

	/** Start through a keeper, which outlives this thread, reaps the process and records each death beside the lock. */
	async #startKept(
		descriptor: SidecarDescriptor,
		version: number | undefined,
		state: SidecarState,
		attempt: number,
		verifyAfterStart: boolean
	): Promise<void> {
		const title = state.title;
		// Out of this node's process group, allowed as the fork is, and a singleton only for its own lock
		const reaper =
			descriptor === this.#reaperDescriptor
				? {
						detached: true,
						fork: true,
						identity: ['--self-pid-file', lockPathFor(REAPER_NAME)],
						stableMs: REAPER_STABLE_MS,
					}
				: {};
		let handed: KeptStart;
		try {
			handed = await this.#keep!(descriptor.command, [...(descriptor.args ?? [])], {
				name: descriptor.name,
				version,
				script: descriptor.script,
				env: process.env,
				restarts: attempt,
				restartMax: RESPAWN_MAX_ATTEMPTS,
				restartBaseMs: timing.respawnBaseMs,
				restartCapMs: RESPAWN_CAP_MS,
				...reaper,
			});
		} catch (error) {
			this.#refuse(
				state,
				error,
				(why) => `refused to spawn the ${title}: ${why}${allowlistHint(why, descriptor.command)}`
			);
			return;
		}

		if (handed.kind === 'adopted') {
			const kept = keptBy(handed.lock);
			this.#joinHeld(descriptor, version, state, handed.child, kept, attempt, handed.lock?.started);
			if (verifyAfterStart && descriptor.verify) void this.#verify(descriptor, state);
			return;
		}

		const started = await awaitKeeper(handed.pidFilePath, handed.token, handed.launcher);
		if ('error' in started && started.takenOver) {
			// Another thread holds the name now, so this one joins whatever it starts rather than reporting a failure
			this.#logger.warn?.(
				`the ${title}'s claim was taken over before its keeper named a pid; this thread will join it`
			);
			this.#rejoinReplacement(descriptor, version, state, 0, attempt);
			return;
		}
		if ('error' in started) {
			state.error = started.error;
			this.#logger.error?.(`the ${title} failed to start: ${started.error}`);
			// A claim given back leaves the name free, and a sibling that starts it is joined
			if (started.gaveBack) this.#rejoinReplacement(descriptor, version, state, 0, attempt);
			return;
		}
		state.pid = started.pid;
		state.started = true;
		state.adopted = false;
		// A process that ended before this thread first looked has no start to read, and its pid may be another's now
		this.#recordTarget(descriptor, state, started.pid, started.started, !started.ended);
		this.#logger.info?.(
			`started the ${title} (pid ${started.pid}) under keeper ${started.keeper}: ${descriptor.command} ${(descriptor.args ?? []).join(' ')}`
		);
		const kept: Kept = {
			token: handed.token,
			keeper: started.keeper,
			keeperArgv: started.keeperArgv,
			since: Date.now(),
		};
		this.#watchKept(descriptor, version, state, started.pid, kept, attempt, started.ended);
		if (verifyAfterStart && descriptor.verify) void this.#verify(descriptor, state);
	}

	/** A holder the lock handed this thread: answered from its keeper's record where it has one, by the claim where not. */
	#joinHeld(
		descriptor: SidecarDescriptor,
		version: number | undefined,
		state: SidecarState,
		child: SpawnedChild,
		kept: Kept | null,
		attempt: number,
		started?: string
	): void {
		state.pid = child.pid;
		state.started = true;
		state.adopted = true;
		if (typeof child.pid === 'number') this.#recordTarget(descriptor, state, child.pid, started);
		this.#logger.info?.(
			`the ${state.title} is already running on this node (pid ${child.pid}); this thread joined it instead of starting a second one`
		);
		// unref stops the wrapper's poll from holding the event loop open, never from polling
		child.unref();
		child.on('exit', () => {
			if (kept && typeof child.pid === 'number') {
				void this.#answerKeptDeath(descriptor, version, state, child.pid, kept, attempt);
				return;
			}
			state.exited = true;
			state.code = undefined;
			state.signal = undefined;
			this.#recoverOwnerlessDeath(descriptor, version, state, child.pid, attempt);
		});
	}

	#watchKept(
		descriptor: SidecarDescriptor,
		version: number | undefined,
		state: SidecarState,
		pid: number,
		kept: Kept,
		attempt: number,
		ended = false
	): void {
		if (ended) {
			void this.#answerKeptDeath(descriptor, version, state, pid, kept, attempt);
			return;
		}
		const watcher = new ExistingProcessWrapper(pid);
		watcher.unref();
		watcher.on('exit', () => void this.#answerKeptDeath(descriptor, version, state, pid, kept, attempt));
	}

	/**
	 * Every thread's answer to a death under a keeper, the thread that launched it included: the keeper's record says
	 * how it ended and what the keeper did, so `exited` is set only once that has been read.
	 */
	async #answerKeptDeath(
		descriptor: SidecarDescriptor,
		version: number | undefined,
		state: SidecarState,
		deadPid: number,
		kept: Kept,
		attempt: number
	): Promise<void> {
		const lockPath = lockPathFor(descriptor.name);
		const record = await awaitKeeperRecord(lockPath, kept, deadPid);
		// A rejoin or a restart has moved this state on to another process since the death
		if (state.pid !== deadPid) return;
		if (record) {
			state.code = record.code ?? undefined;
			state.signal = record.signal ?? undefined;
		}
		state.exited = true;
		if (record && this.#answerKept(descriptor, version, state, record, kept)) return;
		// A keeper whose lock another took writes no record over that keeper's, so the lock says what happened
		const held = record ? null : readPidLock(lockPath);
		if (held && held.token !== kept.token) {
			this.#logger.warn?.(
				`the ${state.title} (pid ${deadPid}) has died and its PID lock no longer names it, so another thread or Harper's own shutdown is handling the death; this thread is not restarting it, and will join whatever replaces it`
			);
			this.#rejoinReplacement(descriptor, version, state, deadPid, attempt);
			return;
		}
		if (!record && identifyKeeper(kept.keeper, kept.keeperArgv) === 'differs') {
			this.#reportNotRunning(state);
			state.error = `died with its keeper (pid ${kept.keeper}) gone, so nothing could read how it ended`;
			this.#logger.warn?.(
				`the ${state.title} (pid ${deadPid}) ${state.error}; it may have been stopped on purpose, so nothing restarts it until the component starts it again`
			);
			return;
		}
		this.#recoverOwnerlessDeath(descriptor, version, state, deadPid, record?.restarts ?? attempt);
	}

	/** True once the record has answered the death; false leaves it to the lock. */
	#answerKept(
		descriptor: SidecarDescriptor,
		version: number | undefined,
		state: SidecarState,
		record: KeeperRecord,
		kept: Kept
	): boolean {
		const title = state.title;
		const deadPid = record.pid || state.pid || 0;
		const cause = record.signal ? `signal ${record.signal}` : `exit code ${record.code}`;
		const hint = !record.signal && descriptor.exitHint ? `. ${descriptor.exitHint}` : '';
		switch (record.outcome) {
			case 'released':
				this.#reportNotRunning(state);
				if (record.error) state.error = `its PID lock could not be released after a deliberate stop: ${record.error}`;
				if (record.signal) this.#logger.warn?.(`the ${title} was terminated by ${record.signal}`);
				else if (record.code === 0) this.#logger.info?.(`the ${title} exited cleanly`);
				else this.#logger.info?.(`the ${title} (pid ${deadPid}) was shut down (${cause}); not restarting it`);
				return true;
			case 'restarting':
				if (record.signal)
					this.#logger.error?.(`the ${title} was terminated by ${record.signal}; that is a crash or an OOM kill`);
				else this.#logger.error?.(`the ${title} exited with code ${record.code}; its keeper restarts it${hint}`);
				this.#logger.warn?.(
					`its keeper is restarting the ${title} in ${record.waitMs}ms after ${cause} (attempt ${record.restarts} of ${RESPAWN_MAX_ATTEMPTS})`
				);
				void this.#rejoinKept(descriptor, version, state, record, kept);
				return true;
			case 'gave-up':
				this.#reportNotRunning(state);
				state.error = `has died ${record.restarts + 1} times (${cause}); not restarting it again until the component reloads`;
				this.#logger.error?.(`the ${title} ${state.error}${hint}`);
				return true;
			case 'failed':
				this.#reportNotRunning(state);
				state.error = `died (${cause}) and its keeper could not start it again: ${record.error ?? 'no reason given'}`;
				this.#logger.error?.(`the ${title} ${state.error}`);
				return true;
			case 'gone':
			case 'taken':
				this.#logger.warn?.(
					`the ${title} (pid ${deadPid}) has died and its PID lock no longer names it, so another thread or Harper's own shutdown is handling the death; this thread is not restarting it, and will join whatever replaces it`
				);
				this.#rejoinReplacement(descriptor, version, state, deadPid, record.restarts);
				return true;
		}
		return false;
	}

	/**
	 * Join the restart a keeper announced, and never start one while that keeper lives: past the cap it releases the
	 * lock, and a thread that claimed it then would start a second. A lock no longer the keeper's goes to the claim.
	 */
	async #rejoinKept(
		descriptor: SidecarDescriptor,
		version: number | undefined,
		state: SidecarState,
		record: KeeperRecord,
		kept: Kept
	): Promise<void> {
		const lockPath = lockPathFor(descriptor.name);
		// The pid this thread last watched, which a crash loop's later record does not name
		const watching = state.pid;
		await delay(Math.max(0, record.at + record.waitMs - Date.now()), undefined, { ref: false });
		let checked = Date.now();
		let identified = 0;
		for (;;) {
			if (state.pid !== watching) return;
			let keeperGone = false;
			// Looked at before the reads below, so a keeper found gone has already written everything it will
			if (Date.now() - checked >= KEEPER_ALIVE_MS) {
				checked = Date.now();
				keeperGone = identifyKeeper(kept.keeper, kept.keeperArgv) === 'differs';
			}
			const held = readPidLock(lockPath);
			const latest = readKeeperRecord(lockPath);
			const newer =
				latest !== null &&
				latest.token === kept.token &&
				(latest.at !== record.at || latest.pid !== record.pid || latest.outcome !== record.outcome);
			if (newer) {
				state.code = latest.code ?? undefined;
				state.signal = latest.signal ?? undefined;
				if (!this.#answerKept(descriptor, version, state, latest, kept))
					this.#recoverOwnerlessDeath(descriptor, version, state, record.pid, latest.restarts);
				return;
			}
			const committed = held?.token === kept.token && held.pid > 0 && held.pid !== record.pid ? held : null;
			// Looked at no more often than this, since each look forks `ps` on darwin
			const due = committed !== null && Date.now() - identified >= KEEPER_IDENTIFY_MS;
			if (due) identified = Date.now();
			if (due && identifyKept(committed.pid, descriptor.command, descriptor.script, committed) === 'match') {
				state.pid = committed.pid;
				state.started = true;
				state.restarts = record.restarts;
				this.#clearDeath(state);
				this.#recordTarget(descriptor, state, committed.pid, committed.started);
				this.#logger.info?.(
					`the ${state.title} runs again under its keeper (pid ${committed.pid}); this thread joined it`
				);
				this.#watchKept(descriptor, version, state, committed.pid, { ...kept, since: Date.now() }, record.restarts);
				// A restart replaced the pid on this state, so the verdict is retaken for the new one
				if (descriptor.verify) void this.#verify(descriptor, state);
				return;
			}
			// No deadline: a live keeper either commits or records, and a claim beside it would start a second
			if (held?.token !== kept.token || keeperGone) {
				// The restart the keeper announced is this thread's to answer now, counted as the same one
				this.#recoverOwnerlessDeath(descriptor, version, state, record.pid, record.restarts - 1);
				return;
			}
			await delay(KEEPER_WATCH_MS, undefined, { ref: false });
		}
	}

	/** Forget the last incarnation's death, or one early exit reads as a dead process beside a live pid forever. */
	#clearDeath(state: SidecarState): void {
		state.exited = undefined;
		state.error = undefined;
		state.code = undefined;
		state.signal = undefined;
	}

	/** A start that could not begin: the reason goes on the state, and into the log in the caller's words. */
	#refuse(state: SidecarState, error: unknown, describe: (why: string) => string): void {
		state.error = errorMessage(error);
		this.#logger.error?.(describe(state.error));
	}

	/** What a thread reports once nothing will replace a process: not the pid that died, and no verdict about it. */
	#reportNotRunning(state: SidecarState): void {
		state.started = false;
		state.pid = undefined;
		state.verified = undefined;
		state.verifyDetail = undefined;
		// With no pid there is nothing for a verdict to be stale against, and leaving the dead one here
		// would make a reader comparing verifiedPid with pid report a restart that did not happen
		state.verifiedPid = undefined;
		state.verifiedAt = undefined;
	}

	/** Launch the detached reaper, or join the one this node already runs; its PID lock makes it a singleton. */
	#ensureReaper(pidDir: string, attempt = 0): Promise<void> {
		// `started`, not presence: a reaper this thread watched die leaves its state behind
		if (this.#reaper?.started) return Promise.resolve();
		// One launch at a time: a second start meanwhile waits on it rather than resetting the state it fills
		this.#reaperStarting ??= this.#launchReaper(pidDir, attempt).finally(() => (this.#reaperStarting = undefined));
		return this.#reaperStarting;
	}

	async #launchReaper(pidDir: string, attempt: number): Promise<void> {
		// The pid names the boot: a replacement node's first start replaces the previous boot's reaper
		// through the lock's identity-checked version mismatch, so no watch window is left open
		const version = fingerprintVersion(REAPER_NAME, process.pid);
		// Reused rather than replaced: a consumer holds this object and reads it on every status request. The
		// fields go back to what a launch starts from, as `#spawnProcess` does at the top of a respawn.
		const state: SidecarState = this.#reaper ?? {
			name: REAPER_NAME,
			title: 'sidecar reaper',
			command: process.execPath,
			version,
			started: false,
		};
		state.version = version;
		state.started = false;
		state.adopted = false;
		state.pid = undefined;
		this.#clearDeath(state);
		this.#reaper = state;
		const logRoot: unknown = env.get(CONFIG_PARAMS.LOGGING_ROOT);
		const args = [
			// A worker thread's process.pid IS the main Harper process: threads share a process
			'--harper-pid',
			String(process.pid),
			'--hdb-pid-file',
			join(env.getHdbBasePath(), HDB_PID_FILE),
			'--pid-dir',
			pidDir,
			'--restart-grace-ms',
			String(REAPER_RESTART_GRACE_MS),
			'--self-pid-file',
			lockPathFor(REAPER_NAME),
			...(typeof logRoot === 'string' ? ['--log', join(logRoot, 'sidecarReaper.log')] : []),
		];

		if (this.#keep) {
			// Under a keeper like any sidecar, so its death is reaped and restarted with no thread left to see it
			this.#reaperDescriptor ??= {
				name: REAPER_NAME,
				title: state.title,
				command: process.execPath,
				args: [REAPER_SCRIPT, ...args],
				script: REAPER_SCRIPT,
				reaper: false,
			};
			try {
				await this.#spawnProcess(this.#reaperDescriptor, version, state, attempt, false);
			} catch (error) {
				this.#refuse(state, error, (why) => `could not start the sidecar reaper: ${why}`);
			}
			return;
		}

		let child: SpawnedChild & { disconnect?: () => void };
		try {
			// The source copy ships in the package and runs under bare node, so one path serves dev and dist
			child = this.#fork!(REAPER_SCRIPT, args, {
				name: REAPER_NAME,
				version,
				detached: true,
				stdio: 'ignore',
				env: process.env,
				execArgv: [],
				// A reaper is this node's only while it carries this lock: another root's reaper is not one to adopt or stop
				identity: ['--self-pid-file', lockPathFor(REAPER_NAME)],
			});
		} catch (error) {
			this.#refuse(
				state,
				error,
				(why) => `could not start the sidecar reaper: ${why}; the sidecars will outlive an ungracefully-stopped node`
			);
			return;
		}

		child.on('error', (error: NodeJS.ErrnoException) => {
			this.#logger.error?.(`the sidecar reaper failed to execute: ${error.message}`);
		});
		state.pid = child.pid;
		state.started = true;
		// When this incarnation came up, so its death can be judged as a crash loop or as a fresh incident
		const launchedAt = Date.now();
		state.adopted = !Array.isArray(child.spawnargs);
		if (state.adopted) {
			// unref stops the wrapper's poll from holding the event loop open, never from polling
			child.unref();
			// A joiner cannot tell a deliberate stop from a kill, so it relaunches either way: the lock-arbitrated
			// fork turns that into an adoption where a replacement exists, and a node on its way out runs no timer.
			child.on('exit', () =>
				this.#reaperDied(
					pidDir,
					state,
					attempt,
					launchedAt,
					`the reaper this thread joined (pid ${child.pid}) has died`
				)
			);
			return;
		}

		// The fork IPC channel would tie the reaper to this thread; close it so the reaper survives the node
		child.disconnect?.();
		child.unref();
		this.#logger.info?.(`sidecar reaper started (pid ${child.pid}), watching the sidecars under ${pidDir}`);
		child.on('exit', (code: number | null, signal: NodeJS.Signals | null) => {
			// Read as a sidecar's exit is: a stop signal or a clean code is deliberate, and anything else is a loss
			const deliberate = isDeliberate(code, signal);
			this.#reaperDied(
				pidDir,
				state,
				attempt,
				launchedAt,
				signal ? `the reaper was terminated by ${signal}` : `the reaper exited with code ${code}`,
				deliberate
			);
		});
	}

	/**
	 * The reaper is gone, and `started` goes with it. A deliberate stop ends here; anything else is relaunched
	 * on a sidecar's schedule through the same lock, and a node inside `process.exit` runs no timer.
	 */
	#reaperDied(
		pidDir: string,
		state: SidecarState,
		attempt: number,
		launchedAt: number,
		why: string,
		deliberate = false
	): void {
		state.exited = true;
		state.started = false;
		state.pid = undefined;
		if (deliberate) {
			this.#logger.info?.(`${why}; this node is not replacing it`);
			return;
		}
		state.error = `${why}. Nothing is reaping this node's processes: if the node dies without running its exit handlers, they outlive it.`;
		this.#logger.warn?.(state.error);
		const next = nextReaperAttempt(attempt, Date.now() - launchedAt);
		if (next === null) {
			this.#logger.error?.(
				`the sidecar reaper has died ${attempt + 1} times without staying up for ${REAPER_STABLE_MS}ms; not replacing it again until the component reloads`
			);
			return;
		}
		const wait = backoffMs(next);
		this.#logger.warn?.(`replacing the sidecar reaper in ${wait}ms (attempt ${next + 1} of ${RESPAWN_MAX_ATTEMPTS})`);
		const timer = setTimeout(() => void this.#ensureReaper(pidDir, next), wait);
		timer.unref?.();
	}

	/**
	 * A joiner's answer to the death of the process it joined. It has no exit status, so the lock is the discriminator:
	 * a deliberate stop has removed or replaced the lock by the time a joiner sees the death, and only a claim restarts.
	 */
	#recoverOwnerlessDeath(
		descriptor: SidecarDescriptor,
		version: number | undefined,
		state: SidecarState,
		deadPid: number | undefined,
		attempt: number
	): void {
		const lockPath = lockPathFor(descriptor.name);
		if (typeof deadPid !== 'number' || !claimDeadPidFileLock(lockPath, deadPid)) {
			this.#logger.warn?.(
				`the ${state.title} this thread joined (pid ${deadPid}) has died and its PID lock no longer names it, so another thread or Harper's own shutdown is handling the death; this thread is not restarting it, and will join whatever replaces it`
			);
			if (typeof deadPid === 'number') this.#rejoinReplacement(descriptor, version, state, deadPid, attempt);
			return;
		}
		// At most one caller can rename a name, so however many threads joined this process, one is here
		this.#logger.warn?.(
			`the ${state.title} (pid ${deadPid}) has died with no thread on this node owning it; this thread claimed its PID lock and is the one restarting it`
		);
		this.#respawn(descriptor, version, state, attempt, 'the death of the process this thread joined');
	}

	/**
	 * What standing down leaves behind: a thread still describing the process it watched die. It waits for
	 * the claim winner's replacement and rejoins through the spawn, which the lock turns into an adoption.
	 */
	#rejoinReplacement(
		descriptor: SidecarDescriptor,
		version: number | undefined,
		state: SidecarState,
		deadPid: number,
		attempt: number
	): void {
		const lockPath = lockPathFor(descriptor.name);
		const waitMs = backoffMs(attempt) + timing.rejoinGraceMs;
		const deadline = Date.now() + waitMs;
		const poll = setInterval(() => {
			const lock = readPidLock(lockPath);
			// Absent or empty, a claim in flight (pid 0) or a version that is not this descriptor's is not the
			// replacement; a rejoin only ever adopts, so it signals nothing
			if (
				lock &&
				lock.pid !== deadPid &&
				(version === undefined || lock.version === version) &&
				isProcessAlive(lock.pid)
			) {
				clearInterval(poll);
				this.#startAgain(descriptor, version, state, attempt);
				return;
			}
			if (Date.now() < deadline) return;
			clearInterval(poll);
			// Nothing came, so stop answering with the pid that died: a deliberate stop ends here too,
			// and reporting a corpse as started and verified is what this thread must not do
			this.#reportNotRunning(state);
			this.#logger.warn?.(
				deadPid > 0
					? `nothing replaced the ${state.title} (pid ${deadPid}) in the ${waitMs}ms after its death; this thread now reports it as not running rather than as the pid that died`
					: `nothing started the ${state.title} in the ${waitMs}ms this thread waited to join it; it reports it as not running`
			);
		}, timing.rejoinPollMs);
		// A node shutting down must not be held open by a thread waiting to rejoin something
		poll.unref?.();
	}

	/** Restart with backoff after a death nothing else recovers from; one thread per death ever gets here. */
	#respawn(
		descriptor: SidecarDescriptor,
		version: number | undefined,
		state: SidecarState,
		attempt: number,
		reason: string
	): void {
		if (attempt + 1 > RESPAWN_MAX_ATTEMPTS) {
			// Counted as the keeper counts it: every death, the one that spent the budget included
			this.#reportNotRunning(state);
			state.error = `has died ${attempt + 1} times (${reason}); not restarting it again until the component reloads`;
			this.#logger.error?.(`the ${state.title} ${state.error}`);
			return;
		}
		const wait = backoffMs(attempt);
		this.#logger.warn?.(
			`restarting the ${state.title} in ${wait}ms after ${reason} (attempt ${attempt + 1} of ${RESPAWN_MAX_ATTEMPTS})`
		);
		const timer = setTimeout(() => this.#startAgain(descriptor, version, state, attempt + 1), wait);
		// A node shutting down must not wait on a restart; outliving the node is the reaper's job, not a timer's
		timer.unref?.();
	}

	/** A start from a timer, where nothing awaits it; what it could not survive lands on the state and the log. */
	#startAgain(descriptor: SidecarDescriptor, version: number | undefined, state: SidecarState, attempt: number): void {
		this.#spawnProcess(descriptor, version, state, attempt).catch((error: unknown) => {
			state.error = errorMessage(error);
			this.#logger.error?.(`could not start the ${state.title} again: ${state.error}`);
		});
	}

	async #verify(descriptor: SidecarDescriptor, state: SidecarState): Promise<void> {
		// Read from the stamp rather than the verdict, which is cleared below and would make every retake
		// call itself the first.
		const reason = state.verifiedPid === undefined ? 'untaken' : 'restarted';
		// Stamped before the proof, which polls while a restart can replace the pid; stamped after, the verdict
		// would record the pid that arrived during the wait rather than the one it proved.
		const proving = state.pid ?? null;
		state.verifiedPid = proving;
		// The verdict goes with the stamp: left standing, it is the replaced process's proof beside a live pid,
		// and a reader comparing verifiedPid with pid cannot see it.
		state.verified = undefined;
		state.verifyDetail = undefined;
		let verdict: { ok: boolean; detail?: string };
		try {
			verdict = await descriptor.verify!(state, { reason });
		} catch (error) {
			verdict = { ok: false, detail: errorMessage(error) };
		}
		// A restart during the wait stamped a newer pid and started its own proof. This one is about a process
		// that is gone, so it is dropped rather than written over the verdict that replaces it.
		if (state.verifiedPid !== proving) return;
		state.verified = verdict.ok;
		state.verifyDetail = verdict.detail;
		// Whatever the proof answered, this is when it answered, so a reader can rate-limit its own retake.
		state.verifiedAt = Date.now();
		const line = `the ${state.title} ${verdict.ok ? 'verified' : 'failed verification'}${verdict.detail ? `: ${verdict.detail}` : ''}`;
		if (verdict.ok) this.#logger.info?.(line);
		else this.#logger.error?.(line);
	}
}
