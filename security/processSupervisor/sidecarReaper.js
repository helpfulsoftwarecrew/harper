'use strict';

// A detached process, run by path and never imported, because SIGKILL fires no handler inside the node.
// Plain CJS on node builtins for a bare node, so it mirrors ./processIdentity.ts rather than requiring it.
const { execFileSync } = require('node:child_process');
const { appendFileSync, existsSync, readdirSync, readFileSync, readlinkSync, realpathSync } = require('node:fs');
const { basename, isAbsolute, join } = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');

// The keeper's lock, gate and start-time reads, the same file a keeper runs from and so no mirror of it
const keeper = require('./sidecarKeeper.js');

/** How often the watched process is checked; a test shortens it with `options.pollMs`. */
const POLL_INTERVAL_MS = 1000;
/** How long a sidecar gets after SIGTERM before SIGKILL; a test shortens it with `options.termGraceMs`. */
const TERM_GRACE_MS = 5000;
const SIDECAR_DESCRIPTOR_SUFFIX = '.sidecar.json';
const { errorMessage, unlinkQuietly } = keeper;

function log(options, message) {
	if (!options.logFile) return;
	try {
		appendFileSync(options.logFile, `${new Date().toISOString()} [sidecar-reaper ${process.pid}] ${message}\n`);
	} catch {
		// A log that cannot be written must not stop the reaping, which is the job
	}
}

/** Same rules as processIdentity's isZombie: dead-but-unreaped answers kill(pid, 0) but runs nothing. */
function isZombie(pid) {
	try {
		if (process.platform === 'linux') {
			// comm is parenthesised and may contain spaces and parens, so the state follows the LAST ')'
			const stat = readFileSync(`/proc/${pid}/stat`, 'utf-8');
			const commEnd = stat.lastIndexOf(')');
			return (
				commEnd !== -1 &&
				stat
					.slice(commEnd + 1)
					.trim()
					.startsWith('Z')
			);
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

/** A command line as darwin's ps prints it, in the keeper's UTF-8 environment whatever this process's locale. */
function psCommandLine(pid, field) {
	return execFileSync('ps', ['-p', String(pid), '-o', field], {
		encoding: 'utf-8',
		timeout: 2000,
		stdio: ['ignore', 'pipe', 'ignore'],
		env: keeper.commandLineEnv(),
	}).trim();
}

function isAlive(pid) {
	// Non-positive values are process-group selectors to kill(2); a containerized Harper IS pid 1
	if (!Number.isInteger(pid) || pid <= 0) return false;
	try {
		process.kill(pid, 0);
	} catch (error) {
		if (error.code !== 'EPERM') return false;
	}
	return !isZombie(pid);
}

function executableOf(pid) {
	if (!isAlive(pid)) return null;
	try {
		if (process.platform === 'linux') return realpathSync(readlinkSync(`/proc/${pid}/exe`));
		if (process.platform === 'darwin') {
			const reported = psCommandLine(pid, 'comm=');
			return reported === '' ? null : reported;
		}
		return null;
	} catch {
		return null;
	}
}

// argv is process-writable where /proc/<pid>/exe is kernel-set: confidence against pid reuse and
// stale locks, not proof against a forger. Same rules and the same caveat as ./processIdentity.ts.
function argumentsOf(pid) {
	if (!isAlive(pid)) return null;
	try {
		if (process.platform === 'linux') {
			const argv = readFileSync(`/proc/${pid}/cmdline`, 'utf-8').split('\0').filter(Boolean);
			return argv.length > 0 ? argv : null;
		}
		if (process.platform === 'darwin') {
			// `args` is the vector re-joined with spaces, so an argument containing one cannot be recovered
			const reported = psCommandLine(pid, 'args=');
			return reported === '' ? null : reported.split(/\s+/);
		}
		return null;
	} catch {
		return null;
	}
}

/** processIdentity's rule: on Linux a sidecar runs as Harper's user, so EPERM or EACCES here is someone else's. */
function isAnotherUsersProcess(pid) {
	if (process.platform !== 'linux') return false;
	try {
		process.kill(pid, 0);
	} catch (error) {
		return error.code === 'EPERM';
	}
	try {
		readlinkSync(`/proc/${pid}/exe`);
	} catch (error) {
		return error.code === 'EACCES';
	}
	return false;
}

function identifyExecutable(pid, command) {
	const actual = executableOf(pid);
	if (actual === null) return 'unknown';
	let expected;
	try {
		expected = realpathSync(command);
	} catch {
		return 'unknown';
	}
	if (isAbsolute(actual)) {
		try {
			return realpathSync(actual) === expected ? 'match' : 'differs';
		} catch {
			return actual === expected ? 'match' : 'differs';
		}
	}
	return basename(actual) === basename(expected) ? 'unknown' : 'differs';
}

/** The script half, on the executable's rules: full-path agreement matches, name-only cannot tell. */
function identifyScript(pid, script) {
	const argv = argumentsOf(pid);
	if (argv === null) return 'unknown';
	let expected;
	try {
		expected = realpathSync(script);
	} catch {
		return 'unknown';
	}
	let sameName = false;
	// argv[0] is the interpreter, which identifyExecutable has already answered for
	for (const argument of argv.slice(1)) {
		if (argument === expected) return 'match';
		try {
			if (realpathSync(argument) === expected) return 'match';
		} catch {
			// Not a readable path; it can still agree by name below
		}
		if (basename(argument) === basename(expected)) sameName = true;
	}
	return sameName ? 'unknown' : 'differs';
}

/** processIdentity's rule: a keeper carries its sidecar's arguments and is never the sidecar, and it runs as node. */
function isKeeperProcess(pid, command) {
	if (basename(command) !== 'node' && basename(command) !== basename(process.execPath)) return false;
	const joined = argumentsOf(pid)?.join(' ') ?? '';
	return joined.includes('/sidecarKeeper.js --keep ') || joined.includes('/sidecarKeeper.js --launch ');
}

/** 'match' | 'differs' | 'unknown', with the same rules as ./processIdentity.ts. */
function identify(pid, command, script) {
	if (!command) return 'unknown';
	if (!isAlive(pid)) return 'differs';
	if (isAnotherUsersProcess(pid)) return 'differs';
	const executable = identifyExecutable(pid, command);
	if (executable !== 'differs' && isKeeperProcess(pid, command)) return 'differs';
	if (!script) return executable;
	if (executable === 'differs') return 'differs';
	// An interpreter is one binary for every script it runs, so both halves must agree before a SIGKILL
	const named = identifyScript(pid, script);
	if (named === 'differs') return 'differs';
	return named === 'unknown' || executable === 'unknown' ? 'unknown' : 'match';
}

/** processIdentity's identifyKept: a recorded start time decides either way, and without one the keeper may vouch. */
function identifyKept(pid, command, script, kept) {
	if (!isAlive(pid)) return 'differs';
	let unread = false;
	if (kept?.started) {
		const started = keeper.startedAt(pid);
		if (started === kept.started) return 'match';
		if (started !== null) return 'differs';
		unread = true;
	}
	const verdict = vouchedFor(pid, identify(pid, command, script), kept);
	// A recorded start that cannot be read now says nothing either way, so it never makes a kept process "not ours"
	return unread && verdict === 'differs' ? 'unknown' : verdict;
}

function vouchedFor(pid, verdict, kept) {
	if (verdict === 'match' || kept?.keeper === undefined || !kept.keeperArgv?.length || kept.keeper <= 1) return verdict;
	if (keeper.parentOf(pid) !== kept.keeper) return verdict;
	const vouched = argvLeads(kept.keeper, kept.keeperArgv);
	return vouched === 'differs' ? verdict : vouched;
}

/** processIdentity's argvLeads: whether `expected` leads the pid's argv, read as this module reads any argv. */
function argvLeads(pid, expected) {
	if (!isAlive(pid)) return 'differs';
	const actual = argumentsOf(pid);
	if (actual === null || expected.length === 0) return 'unknown';
	if (process.platform === 'darwin') {
		const joined = actual.join(' ');
		const want = expected.join(' ');
		return joined === want || joined.startsWith(`${want} `) ? 'match' : 'differs';
	}
	return expected.every((argument, index) => actual[index] === argument) ? 'match' : 'differs';
}

function canIdentify() {
	return process.platform === 'linux' || process.platform === 'darwin';
}

/** sidecarRegistry.ts's readSidecarTargets: every readable `*.sidecar.json` under pidDir, read at reap time. */
function readTargets(options) {
	let entries;
	try {
		entries = readdirSync(options.pidDir);
	} catch {
		return [];
	}
	const targets = [];
	for (const entry of entries.filter((name) => name.endsWith(SIDECAR_DESCRIPTOR_SUFFIX))) {
		try {
			const parsed = JSON.parse(readFileSync(join(options.pidDir, entry), 'utf-8'));
			// A descriptor with no command names nothing the exit-time stop would signal, and nothing this may signal
			if (typeof parsed?.pidFile !== 'string' || typeof parsed.name !== 'string') continue;
			if (typeof parsed.command !== 'string' || !Number.isInteger(parsed.pid)) continue;
			targets.push({
				name: parsed.name,
				pidFile: parsed.pidFile,
				pid: parsed.pid,
				command: parsed.command,
				...(typeof parsed.script === 'string' ? { script: parsed.script } : {}),
				...(typeof parsed.started === 'string' && parsed.started !== '' ? { started: parsed.started } : {}),
			});
		} catch {
			// A descriptor that cannot be read names nothing this may act on
		}
	}
	return targets;
}

/** `target.pid` was recorded by the thread that watched the spawn; `recorded` is whatever the lock says now. */
function pidsToStop(options, target, recorded, kept) {
	const candidates = [...new Set([recorded, target.pid])].filter(
		(candidate) => candidate !== null && isAlive(candidate)
	);
	return candidates.filter((candidate) => {
		if (canIdentify()) {
			// The lock's record for the pid it names, else the descriptor's start time for the pid it recorded
			const record =
				candidate === recorded && kept ? kept : candidate === target.pid && target.started ? target : undefined;
			const verdict = identifyKept(candidate, target.command, target.script, record);
			if (verdict === 'match') return true;
			log(options, `${target.name}: pid ${candidate} is not this sidecar (${verdict}); left alone`);
			return false;
		}
		// No identification here: the descriptor's spawn-time pid is the only defensible fallback
		if (candidate === target.pid) return true;
		log(options, `${target.name}: pid ${candidate} came from the lock and cannot be identified here; left alone`);
		return false;
	});
}

/** The lock goes BEFORE the signal: a file naming a dying process makes a reader adopt a corpse. */
async function reapTarget(options, target) {
	// Read and removed inside its gate, so a restart a keeper commits after the host is gone is what gets stopped
	const held = await keeper.underGate(target.pidFile, (lock) => {
		unlinkQuietly(target.pidFile);
		return lock;
	});
	const recorded = held && held.pid > 0 ? held.pid : null;

	const pids = pidsToStop(options, target, recorded, held?.keeper !== undefined || held?.started ? held : null);
	if (pids.length === 0) {
		log(options, `${target.name}: nothing to stop`);
		unlinkQuietly(join(options.pidDir, `${target.name}${SIDECAR_DESCRIPTOR_SUFFIX}`));
		return;
	}

	for (const pid of pids) {
		try {
			process.kill(pid, 'SIGTERM');
			log(options, `sent SIGTERM to ${pid} (${target.name})`);
		} catch (error) {
			log(options, `could not SIGTERM ${pid}: ${errorMessage(error)}`);
		}
	}

	const graceMs = options.termGraceMs ?? TERM_GRACE_MS;
	const deadline = Date.now() + graceMs;
	while (Date.now() < deadline && pids.some(isAlive)) await delay(100);

	// SIGKILL reaches only what pidsToStop chose: an identified pid, or the spawn-time pid where none can be identified
	for (const pid of pids.filter(isAlive)) {
		try {
			process.kill(pid, 'SIGKILL');
			log(options, `${pid} ignored SIGTERM for ${graceMs}ms; sent SIGKILL`);
		} catch (error) {
			log(options, `could not SIGKILL ${pid}: ${errorMessage(error)}`);
		}
	}
	unlinkQuietly(join(options.pidDir, `${target.name}${SIDECAR_DESCRIPTOR_SUFFIX}`));
}

/** The pid of a replacement node, or null. Never the process this was watching. */
function replacementPid(options) {
	if (!options.hdbPidFile || !existsSync(options.hdbPidFile)) return null;
	const pid = keeper.readLock(options.hdbPidFile)?.pid ?? null;
	if (pid === null || pid === options.harperPid || !isAlive(pid)) return null;
	return pid;
}

/**
 * Its own lock, removed only while it names this reaper with no keeper: a node since restarted may have taken it for
 * a newer reaper, and a keeper releases its own once this exits.
 */
async function releaseSelf(options) {
	if (!options.selfPidFile) return;
	const held = await keeper.underGate(options.selfPidFile, (lock) => {
		if (lock?.pid === process.pid && lock.keeper === undefined) unlinkQuietly(options.selfPidFile);
		return lock;
	});
	if (held && held.pid !== process.pid) log(options, `its lock now names pid ${held.pid}; left it to that reaper`);
}

/** Exported so a test can drive it without spawning a process; the module tail runs it when executed directly. */
async function run(options) {
	log(options, `watching pid ${options.harperPid}; will stop the sidecars under ${options.pidDir} when it goes`);

	while (isAlive(options.harperPid)) await delay(options.pollMs ?? POLL_INTERVAL_MS);
	log(options, `pid ${options.harperPid} is gone`);

	// `harper restart` forks a replacement and exits the old main; its children are KEPT for the
	// replacement to adopt through the identity-checked lock, so reaping waits for one first
	const deadline = Date.now() + options.restartGraceMs;
	while (Date.now() < deadline) {
		const replacement = replacementPid(options);
		if (replacement !== null) {
			log(options, `pid ${replacement} took over within the grace window; leaving the sidecars for it to adopt`);
			await releaseSelf(options);
			return;
		}
		await delay(100);
	}

	for (const target of readTargets(options)) await reapTarget(options, target);
	await releaseSelf(options);
	log(options, 'done.');
}

/** Every flag takes a value; one arriving as the final token has nothing to consume and is dropped. */
function parseArgs(argv) {
	const options = { harperPid: Number.NaN, pidDir: '', restartGraceMs: 8000 };
	for (let i = 0; i < argv.length; i++) {
		const value = argv[i + 1];
		if (value === undefined) break;
		switch (argv[i]) {
			case '--harper-pid':
				options.harperPid = Number.parseInt(value, 10);
				i++;
				break;
			case '--hdb-pid-file':
				options.hdbPidFile = value;
				i++;
				break;
			case '--pid-dir':
				options.pidDir = value;
				i++;
				break;
			case '--restart-grace-ms':
				options.restartGraceMs = Number.parseInt(value, 10);
				i++;
				break;
			case '--self-pid-file':
				options.selfPidFile = value;
				i++;
				break;
			case '--log':
				options.logFile = value;
				i++;
				break;
		}
	}
	return options;
}

module.exports = {
	parseArgs,
	reapTarget,
	run,
	isAlive,
	canIdentify,
	// For the tests that hold these copies to processIdentity.ts's and sidecarRegistry.ts's
	argvLeads,
	identify,
	identifyKept,
	readTargets,
};

if (require.main === module) {
	const options = parseArgs(process.argv.slice(2));
	// A non-positive pid is a process-GROUP selector to kill(2), and a reaper with nothing to watch sits forever
	if (!Number.isInteger(options.harperPid) || options.harperPid <= 0) {
		process.stderr.write('sidecar-reaper: --harper-pid must be a positive integer\n');
		process.exit(2);
	}
	if (!options.pidDir) {
		process.stderr.write('sidecar-reaper: --pid-dir is required\n');
		process.exit(2);
	}
	run(options).catch((error) => {
		process.stderr.write(`sidecar-reaper: ${errorMessage(error)}\n`);
		process.exit(1);
	});
}
