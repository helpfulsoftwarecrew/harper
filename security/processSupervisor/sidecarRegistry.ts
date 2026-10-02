// What survives of a sidecar outside the thread that spawned it: a descriptor beside its PID lock,
// read by the main process at graceful exit and by the detached reaper after an ungraceful one.
import { readdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { threadId } from 'node:worker_threads';

import * as env from '../../utility/environment/environmentManager.ts';
import { HDB_PID_FILE } from '../../utility/hdbTerms.ts';
import hdbLogger from '../../utility/logging/harper_logger.ts';
import { readPidLock, withPidFileLockGate, type PidLock } from './pidFileLock.ts';
import { identifyKept, isProcessAlive } from './processIdentity.ts';

export const SIDECAR_DESCRIPTOR_SUFFIX = '.sidecar.json';
/** How long the exit-time stop waits on one lock's gate: a live holder keeps it for milliseconds, and exit cannot wait long. */
const EXIT_GATE_WAIT_MS = 1000;
let exitGateWaitMs = EXIT_GATE_WAIT_MS;

// Test-only: a suite shortens the wait on a held gate. No argument restores the shipped value, returned.
export function _setExitGateWaitForTests(ms: number = EXIT_GATE_WAIT_MS): number {
	exitGateWaitMs = ms;
	return exitGateWaitMs;
}

export interface SidecarTarget {
	/** The spawn name, which is also the PID-lock filename. */
	name: string;
	/** The lock file naming this sidecar, removed before it is signalled. */
	pidFile: string;
	/** The pid recorded by the thread that watched the spawn (or joined it through the lock). */
	pid: number;
	/** The command it runs, which the pid must positively identify as before the shutdown stop signals it. */
	command: string;
	/** Set when the command is an interpreter: the script that tells this process from its siblings. */
	script?: string;
	/** When `pid` started, so a pid reused since is told from it whatever it runs. */
	started?: string;
}

export function sidecarDescriptorPath(pidDir: string, name: string): string {
	return join(pidDir, `${name}${SIDECAR_DESCRIPTOR_SUFFIX}`);
}

/** Publish via temp-and-rename so the reaper never reads a torn descriptor. */
export function writeSidecarTarget(pidDir: string, target: SidecarTarget): void {
	const path = sidecarDescriptorPath(pidDir, target.name);
	const temp = `${path}.${process.pid}.${threadId}.tmp`;
	writeFileSync(temp, JSON.stringify(target), 'utf-8');
	renameSync(temp, path);
}

/** Every readable descriptor under `pidDir`; a descriptor that cannot be read names nothing to act on. */
export function readSidecarTargets(pidDir: string): SidecarTarget[] {
	let entries: string[];
	try {
		entries = readdirSync(pidDir);
	} catch {
		return [];
	}
	const targets: SidecarTarget[] = [];
	for (const entry of entries.filter((name) => name.endsWith(SIDECAR_DESCRIPTOR_SUFFIX))) {
		try {
			const parsed: unknown = JSON.parse(readFileSync(join(pidDir, entry), 'utf-8'));
			if (typeof parsed !== 'object' || parsed === null) continue;
			const { name, pidFile, pid, command, script, started } = parsed as Record<string, unknown>;
			if (typeof name !== 'string' || typeof pidFile !== 'string' || typeof command !== 'string') continue;
			if (typeof pid !== 'number' || !Number.isInteger(pid)) continue;
			// A command with no script records none, leaving the command the whole identity
			targets.push({
				name,
				pidFile,
				pid,
				command,
				...(typeof script === 'string' ? { script } : {}),
				...(typeof started === 'string' && started !== '' ? { started } : {}),
			});
		} catch {
			// Absent, half-written or not JSON: nothing this may act on
		}
	}
	return targets;
}

function removeQuietly(path: string): void {
	try {
		unlinkSync(path);
	} catch {
		// Absent is the outcome asked for
	}
}

/**
 * SIGTERMs identified sidecars on the main process's exit, only while hdb.pid names this process, which
 * `harper restart` removes first. Synchronous, since 'exit' handlers cannot await; the reaper escalates.
 */
export function stopSidecarsAtExit(): void {
	const rootPath = env.getHdbBasePath();
	if (!rootPath) return;
	if (readPidLock(join(rootPath, HDB_PID_FILE))?.pid !== process.pid) return;

	const pidDir = join(rootPath, 'pids');
	for (const target of readSidecarTargets(pidDir)) {
		// Decided and removed inside the lock's gate, so a restart a keeper commits meanwhile is never left without it
		const pid = withPidFileLockGate(target.pidFile, (held) => stopDecision(pidDir, target, held), exitGateWaitMs);
		if (pid === null) continue;
		try {
			process.kill(pid, 'SIGTERM');
			hdbLogger.info(`stopped the ${target.name} sidecar (pid ${pid}) at shutdown`);
		} catch {
			// ESRCH: it exited between the identification and the signal
		}
	}
}

/** The pid to SIGTERM once the lock is gone, or null when nothing here may be signalled. */
function stopDecision(pidDir: string, target: SidecarTarget, held: PidLock | null): number | null {
	const locked = held?.pid ?? null;
	let pid = locked ?? target.pid;
	if (!isProcessAlive(pid)) {
		removeQuietly(target.pidFile);
		removeQuietly(sidecarDescriptorPath(pidDir, target.name));
		return null;
	}
	// A recorded start time identifies a process through an exec and refuses a reused pid, as the lock does
	const recordedStart = target.started ? { started: target.started } : undefined;
	const kept = held?.started || held?.keeper !== undefined ? held : pid === target.pid ? recordedStart : undefined;
	let identification = identifyKept(pid, target.command, target.script, kept ?? undefined);
	// A lock naming a live stranger was overwritten or its pid reused. The descriptor's spawn-time pid is
	// the only other way back to the sidecar, so it is tried before the files are discarded.
	if (identification === 'differs' && locked !== null && locked !== target.pid && isProcessAlive(target.pid)) {
		const recorded = identifyKept(target.pid, target.command, target.script, recordedStart);
		if (recorded !== 'differs') {
			hdbLogger.warn(
				`the ${target.name} sidecar's PID lock names ${locked}, which is running something else; falling back to the pid ${target.pid} this node recorded when it spawned it`
			);
			pid = target.pid;
			identification = recorded;
		}
	}
	if (identification === 'differs') {
		// Live and demonstrably something else (the pid was reused): the files are stale, the process is not ours
		removeQuietly(target.pidFile);
		removeQuietly(sidecarDescriptorPath(pidDir, target.name));
		return null;
	}
	if (identification === 'unknown') {
		hdbLogger.warn(
			`not stopping the ${target.name} sidecar (pid ${pid}) at shutdown: it could not be positively identified as running ${target.script ? `${target.command} ${target.script}` : target.command}; the sidecar reaper will adjudicate it`
		);
		return null;
	}
	// The lock goes BEFORE the signal: a file naming a dying process makes a reader adopt a corpse.
	// The descriptor stays, so the reaper can escalate a SIGTERM-ignoring child and then remove it.
	removeQuietly(target.pidFile);
	return pid;
}
