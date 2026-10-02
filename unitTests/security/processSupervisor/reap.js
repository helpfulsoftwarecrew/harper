'use strict';

// Reaps what this suite's tests start and fails a describe whose processes outlive it. A pid-directory
// entry is killed only when its argv identifies it as one of this suite's fixtures.

const assert = require('node:assert');
const { execFileSync, spawn } = require('node:child_process');
const { readdirSync, readFileSync, writeSync } = require('node:fs');
const { join } = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');
const { isMainThread } = require('node:worker_threads');

const env = require('#src/utility/environment/environmentManager');
const { argumentsOf, isProcessAlive } = require('#src/security/processSupervisor/processIdentity');

/** What the suite's node fixtures run until killed, and so the marker the sweeps below find them by. */
const LONG_RUNNING = 'setInterval(() => {}, 1 << 30)';

/** The fixtures this suite starts. A pid whose argv matches none of these is not ours to kill. */
const MARKERS = [LONG_RUNNING, 'sidecarReaper.js', 'supervisedProcess.mjs', 'supervisedComponent.mjs'];

/** This run's pid directory; every keeper a test starts carries a lock inside it. */
function runPidDir() {
	return join(env.getHdbBasePath(), 'pids');
}

/**
 * The keepers whose lock is in `dir`, with everything below them: init adopts a keeper, so no walk down from this
 * process finds it, and it restarts whatever of its own is killed before it.
 */
function keptTree(rows, dir) {
	const keepers = [...rows.values()].filter(
		(row) =>
			!row.state.startsWith('Z') &&
			(row.command.includes(`/sidecarKeeper.js --keep --lock ${dir}/`) ||
				row.command.includes(`/sidecarKeeper.js --launch --lock ${dir}/`))
	);
	const found = [...keepers];
	const queue = keepers.map((row) => row.pid);
	while (queue.length > 0) {
		const parent = queue.shift();
		for (const row of rows.values()) {
			if (row.ppid !== parent || row.state.startsWith('Z')) continue;
			found.push(row);
			queue.push(row.pid);
		}
	}
	return found;
}

/** What the exit sweep also recognises: the `sleep` holders the suite starts outside any pid directory. */
const EXIT_MARKERS = [...MARKERS, 'sleep 600', 'sleep 3600'];

const PAUSE = new Int32Array(new SharedArrayBuffer(4));

/** True when the signal was delivered; a pid already gone is the outcome asked for. */
function signal(pid, name) {
	try {
		process.kill(pid, name);
		return true;
	} catch {
		return false;
	}
}

/** Every keeper a lock in `dir` records on its third line, without trusting any of them yet. */
function claimedKeepers(dir) {
	const keepers = new Set();
	let entries;
	try {
		entries = readdirSync(dir);
	} catch {
		return keepers;
	}
	for (const entry of entries.filter((name) => name.endsWith('.pid'))) {
		try {
			const keeper = JSON.parse(readFileSync(join(dir, entry), 'utf-8').split('\n')[2] ?? '').keeper;
			if (Number.isInteger(keeper) && keeper > 1) keepers.add(keeper);
		} catch {
			// No record: a lock no keeper wrote
		}
	}
	return keepers;
}

/** Every pid a lock or descriptor in `dir` names, without trusting any of them yet. */
function claimedPids(dir) {
	const pids = new Set();
	let entries;
	try {
		entries = readdirSync(dir);
	} catch {
		return pids; // the directory is already gone, which is the outcome asked for
	}
	for (const entry of entries) {
		let text;
		try {
			text = readFileSync(join(dir, entry), 'utf-8');
		} catch {
			continue;
		}
		if (entry.endsWith('.pid')) {
			const pid = Number.parseInt(text.trim().split('\n')[0] ?? '', 10);
			if (Number.isInteger(pid) && pid > 1) pids.add(pid);
		} else if (entry.endsWith('.sidecar.json')) {
			try {
				const pid = JSON.parse(text).pid;
				if (Number.isInteger(pid) && pid > 1) pids.add(pid);
			} catch {
				// A half-written descriptor names nothing
			}
		}
	}
	return pids;
}

/**
 * SIGKILL every fixture `dir` still names. Returns how many were killed, so a caller can assert on it.
 *
 * @param {string} dir a test's pid directory
 */
function reapPidDir(dir) {
	let killed = 0;
	// Keepers first, or each restarts the process killed below it; one counts only while it carries a lock in `dir`
	const keepers = [...claimedKeepers(dir)].filter((keeper) =>
		(argumentsOf(keeper)?.join(' ') ?? '').includes(`/sidecarKeeper.js --keep --lock ${dir}/`)
	);
	// SIGTERM, which a keeper forwards before it ends, since a SIGKILL mid-start orphans the child it just spawned
	for (const keeper of keepers) killed += signal(keeper, 'SIGTERM') ? 1 : 0;
	const deadline = Date.now() + 2000;
	while (keepers.some(isProcessAlive) && Date.now() < deadline) Atomics.wait(PAUSE, 0, 0, 20);
	for (const keeper of keepers.filter(isProcessAlive)) signal(keeper, 'SIGKILL');
	for (const pid of claimedPids(dir)) {
		if (pid === process.pid || !isProcessAlive(pid)) continue;
		const argv = argumentsOf(pid);
		// Unreadable argv means "cannot tell", and cannot tell is not permission. Joined, since darwin splits
		// an argument at its spaces and the `-e` fixture's source has them.
		if (!argv || !MARKERS.some((marker) => argv.join(' ').includes(marker))) continue;
		try {
			process.kill(pid, 'SIGKILL');
			killed++;
		} catch {
			// Gone between the check and the signal, which is the outcome asked for
		}
	}
	return killed;
}

/** Every process as ps lists it, keyed by pid, or null where there is no ps to ask. */
function listProcesses() {
	if (process.platform === 'win32') return null;
	let listing;
	try {
		listing = execFileSync('ps', ['-Ao', 'pid=,ppid=,stat=,etime=,command='], {
			encoding: 'utf-8',
			maxBuffer: 1 << 26,
		});
	} catch {
		return null;
	}
	const rows = new Map();
	for (const line of listing.split('\n')) {
		const match = /^\s*(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.*)$/.exec(line);
		if (!match) continue;
		const [, pid, ppid, state, elapsed, command] = match;
		rows.set(Number(pid), { pid: Number(pid), ppid: Number(ppid), state, elapsed, command });
	}
	return rows;
}

/** The live processes below this one, whatever their depth; zombies are dead, and ps is the listing itself. */
function descendants(rows) {
	const children = new Map();
	for (const row of rows.values()) {
		if (!children.has(row.ppid)) children.set(row.ppid, []);
		children.get(row.ppid).push(row);
	}
	const found = [];
	const queue = [process.pid];
	while (queue.length > 0) {
		for (const child of children.get(queue.shift()) ?? []) {
			queue.push(child.pid);
			if (!child.state.startsWith('Z') && !child.command.startsWith('ps -Ao')) found.push(child);
		}
	}
	return found;
}

/** Pids a test started whose parent can die first, so no descendant walk finds them; keyed to their argv. */
const tracked = new Map();

/**
 * Remember a fixture that will outlive its parent, such as a process a shell forked, so the survivor
 * check and the exit sweep still find it once it is parented to pid 1.
 *
 * @param {number} pid
 */
function track(pid) {
	const row = listProcesses()?.get(pid);
	if (row) tracked.set(pid, row.command);
}

/** Tracked pids still running what they ran when tracked; a reused pid runs something else. */
function trackedAlive(rows) {
	const found = [];
	for (const [pid, command] of tracked) {
		const row = rows.get(pid);
		if (row && row.command === command && !row.state.startsWith('Z')) found.push(row);
		else tracked.delete(pid);
	}
	return found;
}

function describeRow(row) {
	return `pid ${row.pid} (parent ${row.ppid}, running ${row.elapsed}): ${row.command}`;
}

function killAll(rows) {
	for (const row of rows) {
		try {
			process.kill(row.pid, 'SIGKILL');
		} catch {
			// Gone between the listing and the signal
		}
		tracked.delete(row.pid);
	}
}

/**
 * Fails the enclosing describe when a process one of its tests started is still running once every test
 * and hook in it has finished: listed, SIGKILLed so nothing outlives the run, then reported.
 */
/** What a describe may have left: its descendants, the keepers of this run's locks, and what it tracked. */
function started(rows) {
	const byPid = new Map();
	for (const row of [...descendants(rows), ...keptTree(rows, runPidDir())]) byPid.set(row.pid, row);
	return [...byPid.values()];
}

function failOnSurvivors() {
	let earlier = new Set();
	global.before(() => {
		const rows = listProcesses();
		earlier = new Set((rows ? started(rows) : []).map((row) => `${row.pid} ${row.command}`));
	});
	global.after(async function () {
		this.timeout(10_000);
		let survivors = [];
		// A fixture SIGTERMed in teardown may still be exiting, so it gets a moment before it counts
		const deadline = Date.now() + 2000;
		for (;;) {
			const rows = listProcesses();
			if (!rows) return;
			survivors = [...started(rows).filter((row) => !earlier.has(`${row.pid} ${row.command}`)), ...trackedAlive(rows)];
			if (survivors.length === 0 || Date.now() >= deadline) break;
			await delay(25);
		}
		killAll(survivors);
		assert.deepStrictEqual(
			survivors.map(describeRow),
			[],
			`${survivors.length} process(es) this describe started outlived it; each was SIGKILLed`
		);
	});
}

// The last net, for a respawn timer firing after the final hook or a run aborted part-way: synchronous,
// since 'exit' listeners cannot await, and it fails the run rather than hiding what it killed.
if (isMainThread && process.platform !== 'win32') {
	process.on('exit', () => {
		const rows = listProcesses();
		if (!rows) return;
		const strays = [
			...descendants(rows).filter((row) => EXIT_MARKERS.some((marker) => row.command.includes(marker))),
			...keptTree(rows, runPidDir()),
			...trackedAlive(rows),
		];
		if (strays.length === 0) return;
		killAll(strays);
		writeSync(
			2,
			`\n*** ${strays.length} processSupervisor test fixture(s) were still running at exit and were SIGKILLed: ***\n` +
				strays.map((row) => `***   ${describeRow(row)}\n`).join('')
		);
		process.exitCode = 1;
	});
}

/** SIGKILL unless told otherwise; a pid that is not positive names a process group to kill(2), so it gets nothing. */
function stopQuietly(pid, { signal: name = 'SIGKILL' } = {}) {
	if (!Number.isInteger(pid) || pid <= 0) return;
	signal(pid, name);
}

function fixture(command, args, unref) {
	const child = spawn(command, args, { stdio: 'ignore' });
	if (unref) child.unref();
	return child;
}

/** A child running this node binary, so it identifies as `process.execPath`. */
function spawnOwnBinary({ unref = false } = {}) {
	return fixture(process.execPath, ['-e', LONG_RUNNING], unref);
}

/** A child that is emphatically not the node binary. */
function spawnForeign({ unref = false } = {}) {
	return fixture('sleep', ['600'], unref);
}

/** sh exec'ing sleep in place: the pid and its start time stay, and the program it runs changes. */
function spawnExecdShell({ unref = false } = {}) {
	return fixture('/bin/sh', ['-c', 'exec sleep 600'], unref);
}

/** The live processes whose command line carries `marker`, the keepers among them unless `keepers` is false. */
function runningWith(marker, { keepers = true } = {}) {
	const rows = listProcesses();
	// A check that nothing runs must not pass because it could not look
	if (rows === null) {
		if (process.platform === 'win32') return [];
		throw new Error('ps could not list processes, so what is running cannot be told');
	}
	return [...rows.values()]
		.filter((row) => row.command.includes(marker) && !row.command.startsWith('ps '))
		.filter((row) => keepers || !row.command.includes('sidecarKeeper.js'))
		.map((row) => row.pid)
		.filter((pid) => isProcessAlive(pid));
}

module.exports = {
	LONG_RUNNING,
	MARKERS,
	claimedPids,
	failOnSurvivors,
	reapPidDir,
	runningWith,
	spawnExecdShell,
	spawnForeign,
	spawnOwnBinary,
	stopQuietly,
	track,
};
