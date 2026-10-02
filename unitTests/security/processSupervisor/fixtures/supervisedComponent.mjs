// A component that reaches child_process itself instead of scope.processes. The loader substitutes the
// constrained, PID-locked spawn for this import, which is the non-sidecar supervision path.
import { spawn } from 'node:child_process';

/** Starts the named process, or joins the one already running under that name, and records its death. */
export function runProcess(name, command, args) {
	const child = spawn(command, args, { name, stdio: ['ignore', 'ignore', 'ignore'] });
	// The adoption wrapper has no spawnargs; an ignored-stdio winner has no stdout either, so that is not a tell
	const record = {
		pid: child.pid,
		adopted: !Array.isArray(child.spawnargs),
		exited: false,
		exits: 0,
		code: undefined,
		signal: undefined,
	};
	// What every component does with a process it did not start
	child.unref();
	child.on('exit', (code, signal) => {
		record.exits += 1;
		record.exited = true;
		record.code = code;
		record.signal = signal;
	});
	return record;
}
