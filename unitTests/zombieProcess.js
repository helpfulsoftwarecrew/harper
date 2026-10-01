'use strict';

// A real zombie: sh starts a short-lived child, then execs sleep, which keeps the pid and never waits,
// so the child stays unreaped until the holder dies. Needs /bin/sh, and ps off Linux; callers skip elsewhere.

const { execFileSync, spawn } = require('node:child_process');
const { readFileSync } = require('node:fs');
const { waitFor } = require('./waitFor.js');

/** The single-character process state as the platform reports it, or null once the pid is fully gone. */
function processState(pid) {
	try {
		if (process.platform === 'linux') {
			const stat = readFileSync(`/proc/${pid}/stat`, 'utf-8');
			return (
				stat
					.slice(stat.lastIndexOf(')') + 1)
					.trim()
					.charAt(0) || null
			);
		}
		return (
			execFileSync('ps', ['-p', String(pid), '-o', 'state='], {
				encoding: 'utf-8',
				stdio: ['ignore', 'pipe', 'ignore'],
			})
				.trim()
				.charAt(0) || null
		);
	} catch {
		return null;
	}
}

/** Spawns a holder whose dead child stays a zombie; resolves once the platform reports state Z. */
async function makeZombie() {
	const holder = spawn('/bin/sh', ['-c', 'sleep 0.05 & echo $!; exec sleep 600'], {
		stdio: ['ignore', 'pipe', 'ignore'],
	});
	let output = '';
	holder.stdout.on('data', (chunk) => (output += chunk));
	const zombiePid = Number.parseInt(
		String(await waitFor(() => output.trim(), { message: 'sh never printed the child pid' })),
		10
	);
	await waitFor(() => processState(zombiePid) === 'Z', { message: `pid ${zombiePid} never turned zombie` });
	return {
		zombiePid,
		release() {
			try {
				holder.kill('SIGKILL');
			} catch {
				// Already gone
			}
		},
	};
}

module.exports = { makeZombie, processState };
