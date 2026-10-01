'use strict';
// Whether a pid read from a pid file is still a live process that could have written it; kill(pid, 0) only says
// the number is in use. null means "cannot tell", which a caller must not read as "not Harper".

const { execFileSync } = require('node:child_process');
const { readFileSync, readlinkSync, realpathSync } = require('node:fs');

/** The state in /proc/<pid>/stat: the token after the last ')', since `comm` may hold spaces and parens. */
function parseProcStatState(stat) {
	return (
		stat
			.slice(stat.lastIndexOf(')') + 1)
			.trim()
			.split(/\s+/)[0] ?? ''
	);
}

/** Whether anything holds this pid, a dead-but-unreaped zombie included: one syscall, no state read. */
function pidIsHeld(pid) {
	// kill(2) reads 0 and values below -1 as a process group, and -1 as every process it may signal, never one pid
	if (!Number.isInteger(pid) || pid <= 0) return false;
	try {
		process.kill(pid, 0);
	} catch (error) {
		// EPERM: it exists and belongs to another user.
		if (error.code !== 'EPERM') return false;
	}
	return true;
}

function isZombie(pid) {
	try {
		if (process.platform === 'linux') {
			return parseProcStatState(readFileSync(`/proc/${pid}/stat`, 'utf-8')) === 'Z';
		}
		if (process.platform === 'darwin') {
			const state = execFileSync('ps', ['-p', String(pid), '-o', 'state='], {
				encoding: 'utf-8',
				timeout: 2000,
				stdio: ['ignore', 'pipe', 'ignore'],
			}).trim();
			return state.startsWith('Z');
		}
	} catch {
		// An unreadable state says nothing; liveness has already been answered by kill(pid, 0)
	}
	return false;
}

/** Whether some process holds this pid AND, on Linux and darwin, is not a zombie. EPERM still counts as held. */
function isProcessAlive(pid) {
	return pidIsHeld(pid) && !isZombie(pid);
}

/** The executable behind a pid as the platform describes it, or null when it cannot be established. Null covers
 * an unreadable platform, another user's process on Linux, and a pid that exited while being asked. */
function executableOf(pid) {
	if (!isProcessAlive(pid)) return null;
	try {
		if (process.platform === 'linux') {
			// The kernel's own answer, which argv cannot rewrite; a replaced binary reads "/path (deleted)"
			return realpathSync(readlinkSync(`/proc/${pid}/exe`));
		}
		if (process.platform === 'darwin') {
			// `comm` is argv[0] as the process now holds it: a path, a bare name found on PATH, or a title it set
			const reported = execFileSync('ps', ['-p', String(pid), '-o', 'comm='], {
				encoding: 'utf-8',
				timeout: 2000,
				stdio: ['ignore', 'pipe', 'ignore'],
			}).trim();
			return reported === '' ? null : reported;
		}
		// Windows and anything else cannot say, which a caller must not read as "not Harper"
		return null;
	} catch {
		return null;
	}
}

module.exports = { executableOf, isProcessAlive, parseProcStatState, pidIsHeld };
