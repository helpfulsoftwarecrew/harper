// The constrained `child_process` Harper substitutes for a component, and the keeper-backed spawn of scope.processes,
// beside the PID lock rather than in jsLoader.ts, whose job is module admission. Nothing here runs at module scope.

import type { EventEmitter } from 'node:events';
import { mkdirSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import * as child_process from 'node:child_process';

import * as env from '../../utility/environment/environmentManager';
import { CONFIG_PARAMS } from '../../utility/hdbTerms.ts';
import { ExistingProcessWrapper } from './adoptionWrapper.ts';
import {
	acquirePidFileClaim,
	acquirePidFileLockAsync,
	commitPidFileLock,
	readPidLock,
	releasePidFileClaim,
	releaseUnstartedPidFileLock,
	type PidLock,
} from './pidFileLock.ts';
import { KEEPER_SCRIPT } from './processIdentity.ts';

/** How long a child whose commit was lost gets after SIGTERM before SIGKILL. */
const LOST_COMMIT_GRACE_MS = 5000;
let lostCommitGraceMs = LOST_COMMIT_GRACE_MS;

// Test-only: a suite shortens the grace rather than sitting it out. No argument restores the shipped value, returned.
export function _setLostCommitGraceForTests(ms: number = LOST_COMMIT_GRACE_MS): number {
	lostCommitGraceMs = ms;
	return lostCommitGraceMs;
}

export function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

/** Where every PID lock lives. */
export function pidDirectory(): string {
	return join(env.getHdbBasePath(), 'pids');
}

/** The lock a name claims, which the lifecycle reads back by the same rule the spawn claimed it by. */
export function lockPathFor(name: string): string {
	return join(pidDirectory(), `${name}.pid`);
}

/** What the constrained spawn returns: a real ChildProcess, or the adoption wrapper for lock losers. */
export type SpawnedChild = EventEmitter & { pid?: number; spawnargs?: string[]; unref(): void };

export type LockedSpawn = (
	command: string,
	args: string[],
	options: {
		name: string;
		version?: number;
		script?: string;
		stdio: ['ignore', 'ignore', 'ignore'];
		env: NodeJS.ProcessEnv;
	}
) => SpawnedChild;

/** The constrained fork: always allowed (it launches this node binary) and still PID-locked. */
export type LockedFork = (
	modulePath: string,
	args: string[],
	options: {
		name: string;
		version?: number;
		detached: boolean;
		stdio: 'ignore';
		env: NodeJS.ProcessEnv;
		execArgv: string[];
		/** Arguments a holder of this lock must carry, such as the lock a singleton was started for. */
		identity?: string[];
	}
) => SpawnedChild & { disconnect?: () => void };

/** What the keeper-backed spawn is given: the constrained spawn's options, plus the keeper's restart budget. */
export interface KeptSpawnOptions {
	name: string;
	version?: number;
	script?: string;
	env: NodeJS.ProcessEnv;
	/** Restarts already made, which count toward the cap. */
	restarts: number;
	restartMax: number;
	restartBaseMs: number;
	restartCapMs: number;
	/** How long a process must run before its death restarts the count; unset, the count never restarts. */
	stableMs?: number;
	/** Arguments a holder of this lock must carry, such as the lock a singleton was started for. */
	identity?: string[];
	/** Out of this node's process group, so a signal to the group spares what has to outlive the node. */
	detached?: boolean;
	/** This node binary, which the constrained fork allows without the allowlist; the reaper is the one caller. */
	fork?: boolean;
}

/** A live holder to join, or this thread's claim with the keeper launched to commit a pid under it. */
export type KeptStart =
	| { kind: 'adopted'; child: ExistingProcessWrapper; lock: PidLock | null }
	| { kind: 'launched'; token: string; launcher: child_process.ChildProcess; pidFilePath: string };

export type KeptSpawn = (command: string, args: string[], options: KeptSpawnOptions) => Promise<KeptStart>;

function assertAllowed(command: string): void {
	// componentLoader imports this module, so it can load before the config is resolved; a value
	// captured out here would pin an empty allowlist, and an undefined base path, for the life of
	// the process. Anything but a configured list denies.
	const allowedCommands = env.get(CONFIG_PARAMS.APPLICATIONS_ALLOWEDSPAWNCOMMANDS);
	if (!Array.isArray(allowedCommands) || !allowedCommands.includes(command.split(' ')[0])) {
		throw new Error(`Command ${command} is not allowed`);
	}
}

/**
 * The spawn scope.processes uses on Linux and darwin: the same allowlist and lock, and on a won lock a keeper
 * (sidecarKeeper.js) launched to start the process, commit its pid under this claim and outlive the thread.
 */
export async function spawnKept(command: string, args: string[], options: KeptSpawnOptions): Promise<KeptStart> {
	if (!options?.fork) assertAllowed(command);
	if (!options?.name) throw new Error('A kept process must have a "name", which is its PID-lock filename');
	mkdirSync(pidDirectory(), { recursive: true });
	const pidFilePath = lockPathFor(options.name);
	const expected = options.fork ? command : command.split(' ')[0];
	const held = await acquirePidFileLockAsync(
		pidFilePath,
		expected,
		options.script,
		options.version,
		undefined,
		undefined,
		options.identity
	);
	if (held.pid !== 0) {
		// Read while the lock still names it: the death is answered from whatever keeper it records
		const lock = readPidLock(pidFilePath);
		return { kind: 'adopted', child: new ExistingProcessWrapper(held.pid), lock: lock?.pid === held.pid ? lock : null };
	}
	const token = held.token!;
	const flags = [
		'--lock',
		pidFilePath,
		'--token',
		token,
		'--version',
		String(options.version ?? 0),
		'--host-pid',
		String(process.pid),
		'--restarts',
		String(options.restarts),
		'--restart-max',
		String(options.restartMax),
		'--restart-base-ms',
		String(options.restartBaseMs),
		'--restart-cap-ms',
		String(options.restartCapMs),
		...(options.stableMs ? ['--stable-ms', String(options.stableMs)] : []),
		'--',
		command,
		...args,
	];
	let launcher: child_process.ChildProcess;
	try {
		// Detached only on request: a sidecar's keeper stays in this node's process group, as a direct spawn would
		launcher = child_process.spawn(process.execPath, [KEEPER_SCRIPT, '--launch', ...flags], {
			stdio: 'ignore',
			env: options.env,
			detached: options.detached === true,
		});
	} catch (error) {
		await releaseUnstartedPidFileLock(pidFilePath, token);
		throw error;
	}
	return { kind: 'launched', token, launcher, pidFilePath };
}

function createSpawn(spawnFunction: (...args: any) => child_process.ChildProcess, alwaysAllow?: boolean) {
	return function (command: string, args?: any, options?: any, callback?: (...args: any[]) => void) {
		if (!alwaysAllow) assertAllowed(command);
		const processName = options?.name;
		if (!processName)
			throw new Error(
				`Calling ${spawnFunction.name} in Harper must have a process "name" in the options to ensure that a single process is started and reused`
			);
		const requestedVersion = options?.version;

		// Ensure PID directory exists
		mkdirSync(pidDirectory(), { recursive: true });

		const pidFilePath = lockPathFor(processName);

		// fork launches this node binary itself, so that is what the pid behind its lock must identify as
		const isFork = spawnFunction === child_process.fork;
		const expectedCommand = isFork ? process.execPath : command.split(' ')[0];
		// An interpreter is one binary for every script it runs, so the script is the rest of the identity:
		// a fork's module path is always it, and a caller spawning one by hand declares it as `script`
		const expectedScript: string | undefined = isFork ? command : options?.script;
		// Try to acquire lock - returns pid: 0 and the claim's token if acquired, or existing PID/version
		const existing = acquirePidFileClaim(
			pidFilePath,
			expectedCommand,
			expectedScript,
			requestedVersion,
			undefined,
			undefined,
			options?.identity
		);

		if (existing.pid !== 0) {
			// Existing process is running, return wrapper
			return new ExistingProcessWrapper(existing.pid);
		}

		// We acquired the lock (file was created), spawn new process
		const token = existing.token!;
		let childProcess: child_process.ChildProcess;
		try {
			childProcess = spawnFunction(command, args, options, callback);
		} catch (error) {
			releasePidFileClaim(pidFilePath, token);
			throw error;
		}
		// A spawn with no pid reports its failure as an 'error' event, so the caller gets the child and the name is free
		if (!childProcess.pid) {
			releasePidFileClaim(pidFilePath, token);
			return childProcess;
		}

		// Written under the gate over this call's own claim only, so a claim taken over meanwhile keeps its taker's process
		const pidFileContent =
			requestedVersion != null ? `${childProcess.pid}\n${requestedVersion}` : `${childProcess.pid}`;
		let committed: string;
		try {
			committed = commitPidFileLock(pidFilePath, token, pidFileContent);
		} catch (err) {
			committed = errorMessage(err);
		}
		if (committed !== 'written') {
			// No lock names it, so this is its only stop: SIGTERM, then SIGKILL after a grace, as a keeper stops one
			childProcess.kill();
			const escalate = setTimeout(() => childProcess.kill('SIGKILL'), lostCommitGraceMs);
			escalate.unref();
			childProcess.once('exit', () => clearTimeout(escalate));
			throw new Error(`the PID lock for ${processName} could not name the process just started (${committed})`);
		}

		// Clean up PID file when process exits
		childProcess.on('exit', () => {
			try {
				unlinkSync(pidFilePath);
			} catch {
				// File may already be removed
			}
		});

		return childProcess;
	};
}

/**
 * What `jsLoader` puts in a component's module graph in place of `node:child_process`. The name is the
 * contract: REPLACED_BUILTIN_MODULES binds this object under exactly this identifier.
 */
export const child_processConstrained: any = {
	exec: createSpawn(child_process.exec),
	execFile: createSpawn(child_process.execFile),
	fork: createSpawn(child_process.fork, true), // this is launching node, so deemed safe
	spawn: createSpawn(child_process.spawn),
	execSync: function () {
		throw new Error('execSync is not allowed');
	},
};
child_processConstrained.default = child_processConstrained;
