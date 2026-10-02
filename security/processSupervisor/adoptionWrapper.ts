// The handle a thread that lost the PID-lock race reports the winner through. Its liveness poll is its only
// source of 'exit': without it a joiner reports a corpse as running.

import { EventEmitter } from 'node:events';

import { isProcessAlive, pidIsHeld } from './processIdentity.ts';

const PROCESS_CHECK_INTERVAL_MS = 1000;
// Linux reads the process state from procfs on every poll; darwin forks ps for it, so every tenth
const DARWIN_STATE_READ_EVERY = 10;

let checkIntervalMs = PROCESS_CHECK_INTERVAL_MS;

// Test-only: a suite shortens the poll, and darwin still reads the state every tenth one. No argument
// restores the shipped interval; the one in effect is returned, so a test can pin what ships.
export function _setPollIntervalForTests(ms: number = PROCESS_CHECK_INTERVAL_MS): number {
	checkIntervalMs = ms;
	return checkIntervalMs;
}

/**
 * Creates a ChildProcess-like object for an existing process
 */
export class ExistingProcessWrapper extends EventEmitter {
	pid: number;
	private checkInterval: NodeJS.Timeout;

	constructor(pid: number) {
		super();
		this.pid = pid;

		// Monitor process and emit exit event when it terminates. kill(pid, 0) alone answers for a
		// dead-but-unreaped zombie forever, so the process state has to be read as well
		let polls = 0;
		this.checkInterval = setInterval(() => {
			polls += 1;
			const readState = process.platform !== 'darwin' || polls % DARWIN_STATE_READ_EVERY === 0;
			if (readState ? isProcessAlive(pid) : pidIsHeld(pid)) return;
			// Process no longer exists, or holds its pid without running
			clearInterval(this.checkInterval);
			this.emit('exit', null, null);
		}, checkIntervalMs);
	}

	// Kill the process
	kill(signal?: NodeJS.Signals | number) {
		try {
			process.kill(this.pid, signal);
			return true;
		} catch {
			return false;
		}
	}

	// Releases the event loop without stopping the poll, which is this thread's only notice of the death
	unref() {
		this.checkInterval.unref();
		return this;
	}
}
