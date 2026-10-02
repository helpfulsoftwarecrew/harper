// Who gets to restart a process whose death a thread observed without owning it, decided under the PID lock's
// gate as every other decision about the lock is.
import { renameSync, unlinkSync } from 'node:fs';

import { readPidLock, tryPidFileLockGate, type PidLock } from './pidFileLock.ts';
import { identifyKeeper, isProcessAlive } from './processIdentity.ts';

/** How long a claim waits for the gate before leaving the death to whoever holds it. */
const CLAIM_GATE_WAIT_MS = 2000;
let claimGateWaitMs = CLAIM_GATE_WAIT_MS;

// Test-only: a suite shortens the wait on a held gate. No argument restores the shipped value, returned.
export function _setClaimGateWaitForTests(ms: number = CLAIM_GATE_WAIT_MS): number {
	claimGateWaitMs = ms;
	return claimGateWaitMs;
}

/** Whether the keeper a committed lock records is still running as that lock's keeper. */
function keeperOwesRestart(lock: PidLock): boolean {
	if (lock.keeper === undefined || lock.keeperArgv === undefined) return false;
	return identifyKeeper(lock.keeper, lock.keeperArgv) !== 'differs';
}

/**
 * Claims the right to restart a process whose death a thread observed without owning it: true for at most one caller
 * per death, decided under the lock's gate, and false when a holder keeps the gate past CLAIM_GATE_WAIT_MS.
 */
export function claimDeadPidFileLock(pidFilePath: string, deadPid: number): boolean {
	if (!Number.isInteger(deadPid) || deadPid <= 0) return false;
	// A lock that is gone, or names something else, says the death is already someone's: the thread that
	// started it removes the lock on the exit event, and shutdown removes it before its SIGTERM
	if (readPidLock(pidFilePath)?.pid !== deadPid) return false;
	// Decided under the gate, so a sibling's fresh claim cannot land between the last read and the removal
	const claimed = tryPidFileLockGate(pidFilePath, () => claimUnderGate(pidFilePath, deadPid), claimGateWaitMs);
	return claimed === true;
}

function claimUnderGate(pidFilePath: string, deadPid: number): boolean {
	const lock = readPidLock(pidFilePath);
	if (lock?.pid !== deadPid) return false;
	// Something now holds the number, so the lock is no longer this caller's to claim
	if (isProcessAlive(deadPid)) return false;
	// A keeper restarts its own process, so a claim beside a live one would start a second
	if (keeperOwesRestart(lock)) return false;
	// Rename rather than unlink, so a gate broken under a stalled caller still leaves one winner
	const claimed = `${pidFilePath}.${deadPid}.claimed`;
	try {
		renameSync(pidFilePath, claimed);
	} catch {
		// ENOENT: a sibling renamed it first
		return false;
	}
	try {
		unlinkSync(claimed);
	} catch {
		// The rename already decided this; a file left behind changes no decision anyone makes
	}
	return true;
}
