'use strict';

// The one supervisor that escalates to SIGKILL, so these tests prove what it will not signal. Unable to
// identify, it falls back to the pid recorded at spawn, never one read from a lock.

const assert = require('node:assert');
const { spawn } = require('node:child_process');
const { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');

const { asAnotherUser } = require('./anotherUser.js');
const {
	LONG_RUNNING,
	failOnSurvivors,
	spawnExecdShell,
	spawnForeign,
	spawnOwnBinary,
	stopQuietly,
	track,
} = require('./reap.js');

const { waitFor } = require('../../waitFor.js');
const { parseArgs, reapTarget, run, isAlive, canIdentify } = require('#js/security/processSupervisor/sidecarReaper');
const { REAPER_SCRIPT } = require('#src/security/processSupervisor/sidecarLifecycle');
const { identifyProcess, startedAt } = require('#src/security/processSupervisor/processIdentity');

const DEAD_PID = 2147483646;
// The shipped poll and SIGTERM grace are a second and five; these tests shorten both through the options
const POLL_MS = 50;
const TERM_GRACE_MS = 250;

/** A live child that ignores SIGTERM, for the escalation path; touches `readyFile` once the handler holds. */
function spawnStubborn(readyFile) {
	const script = `process.on('SIGTERM', () => {}); require('node:fs').writeFileSync(process.argv[1], ''); ${LONG_RUNNING}`;
	const child = spawn(process.execPath, ['-e', script, readyFile], { stdio: 'ignore' });
	child.unref();
	return child;
}

describe('sidecarReaper', function () {
	failOnSurvivors();
	this.timeout(30000);
	let dir;

	const opts = (over = {}) => ({
		harperPid: process.pid,
		pidDir: dir,
		restartGraceMs: 50,
		pollMs: POLL_MS,
		termGraceMs: TERM_GRACE_MS,
		...over,
	});

	/** The lock and descriptor a running sidecar leaves behind, as sidecarLifecycle records them. */
	function writeTarget(name, pid, command, script) {
		const pidFile = join(dir, `${name}.pid`);
		writeFileSync(pidFile, `${pid}\n1`);
		const target = { name, pidFile, pid, command, script };
		writeFileSync(join(dir, `${name}.sidecar.json`), JSON.stringify(target));
		return target;
	}

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), 'sidecar-reaper-'));
	});

	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
	});

	describe('reapTarget', () => {
		it('stops an identified sidecar and removes its lock and descriptor', async () => {
			const child = spawnOwnBinary({ unref: true });
			try {
				await waitFor(() => isAlive(child.pid));
				const target = writeTarget('agent', child.pid, process.execPath);
				await reapTarget(opts(), target);
				assert.strictEqual(isAlive(child.pid), false, 'the sidecar outlived its reaping');
				// Removed BEFORE the signal: a lock naming a dying process makes a reader adopt a corpse
				assert.strictEqual(existsSync(target.pidFile), false);
				assert.strictEqual(existsSync(join(dir, 'agent.sidecar.json')), false);
			} finally {
				stopQuietly(child.pid);
			}
		});

		it('decides on the pid the lock names inside its gate, so a restart a keeper committed meanwhile is stopped', async function () {
			if (process.platform === 'win32') this.skip();
			const died = spawnOwnBinary({ unref: true });
			const restarted = spawnOwnBinary({ unref: true });
			try {
				await waitFor(() => isAlive(died.pid) && isAlive(restarted.pid));
				const target = writeTarget('agent', died.pid, process.execPath);
				process.kill(died.pid, 'SIGKILL');
				await waitFor(() => !isAlive(died.pid));
				// A keeper holds the gate while it commits its restart, which is what the reaper must wait out
				const gate = `${target.pidFile}.claiming`;
				writeFileSync(gate, String(process.pid));
				const reaping = reapTarget(opts(), target);
				await delay(100);
				writeFileSync(target.pidFile, `${restarted.pid}\n1`);
				rmSync(gate);
				await reaping;
				assert.strictEqual(
					isAlive(restarted.pid),
					false,
					'the restart committed while the reaper waited was left running'
				);
				assert.strictEqual(existsSync(target.pidFile), false);
			} finally {
				stopQuietly(died.pid);
				stopQuietly(restarted.pid);
			}
		});

		it('stops a kept sidecar that exec`d, by the start time its lock records', async function () {
			if (!canIdentify()) this.skip();
			const child = spawnExecdShell();
			child.unref();
			try {
				await waitFor(() => identifyProcess(child.pid, '/bin/sh') === 'differs', { message: 'sh never exec`d' });
				const target = writeTarget('wrapped', child.pid, '/bin/sh');
				const kept = { token: 'kept-token', host: process.pid, started: startedAt(child.pid) };
				writeFileSync(target.pidFile, `${child.pid}\n1\n${JSON.stringify(kept)}\n`);
				await reapTarget(opts(), target);
				assert.strictEqual(isAlive(child.pid), false, 'a kept sidecar that exec`d outlived its reaping');
			} finally {
				stopQuietly(child.pid);
			}
		});

		// The lock's start time for the pid it names, the descriptor's for the pid it recorded: either decides both ways
		for (const [label, recordIn] of [
			['the lock', 'lock'],
			['the descriptor', 'descriptor'],
		]) {
			it(`NEGATIVE: a pid running the same binary with another start time than ${label} records is left alone`, async function () {
				if (!canIdentify()) this.skip();
				const stranger = spawnOwnBinary({ unref: true });
				try {
					await waitFor(() => isAlive(stranger.pid) && startedAt(stranger.pid) !== null);
					const target = writeTarget('agent', stranger.pid, process.execPath);
					const other = 'Thu Jan  1 00:00:00 1970';
					if (recordIn === 'lock') {
						writeFileSync(target.pidFile, `${stranger.pid}\n1\n${JSON.stringify({ token: 't', started: other })}\n`);
					} else {
						rmSync(target.pidFile);
						target.started = other;
					}
					await reapTarget(opts(), target);
					assert.strictEqual(isAlive(stranger.pid), true, `a reused pid was signalled against ${label}'s start time`);
				} finally {
					stopQuietly(stranger.pid);
				}
			});
		}

		it('NEGATIVE: a lock naming a pid that runs another program is never signalled, and the recorded pid still is', async function () {
			if (process.platform === 'win32') this.skip();
			const foreign = spawnForeign({ unref: true });
			const recorded = spawnOwnBinary({ unref: true });
			try {
				await waitFor(() => isAlive(foreign.pid) && isAlive(recorded.pid));
				// The lock names something else entirely, which is what pid reuse produces
				const target = writeTarget('agent', recorded.pid, process.execPath);
				writeFileSync(target.pidFile, `${foreign.pid}\n1`);

				await reapTarget(opts(), target);

				assert.strictEqual(isAlive(foreign.pid), true, 'the reaper signalled a process it had no grounds to name');
				assert.strictEqual(isAlive(recorded.pid), false, 'and it must still stop the one it recorded');
			} finally {
				stopQuietly(foreign.pid);
				stopQuietly(recorded.pid);
			}
		});

		it('NEGATIVE: where the platform can identify, a mismatch is refused even for the recorded pid', async function () {
			if (process.platform === 'win32') this.skip();
			const foreign = spawnForeign({ unref: true });
			try {
				await waitFor(() => isAlive(foreign.pid));
				// Recorded pid and lock agree, and both are wrong: this is not the expected binary
				const target = writeTarget('agent', foreign.pid, process.execPath);
				await reapTarget(opts(), target);

				if (canIdentify()) {
					assert.strictEqual(isAlive(foreign.pid), true, 'identification was available and the mismatch was signalled');
				} else {
					// Stated rather than skipped: the recorded-pid fallback signals here, and that cost is worth seeing
					assert.strictEqual(isAlive(foreign.pid), false);
				}
			} finally {
				stopQuietly(foreign.pid);
			}
		});

		it('NEGATIVE: a pid reused by another node script is not this sidecar', async function () {
			if (!canIdentify()) this.skip();
			const script = join(dir, 'agent.js');
			writeFileSync(script, `${LONG_RUNNING}\n`);
			const sidecar = spawn(process.execPath, [script], { stdio: 'ignore' });
			const stranger = spawnOwnBinary({ unref: true });
			try {
				await waitFor(() => isAlive(sidecar.pid) && isAlive(stranger.pid));
				// Both run this node binary, and the lock names the stranger, as pid reuse leaves it
				const target = writeTarget('agent', sidecar.pid, process.execPath, script);
				writeFileSync(target.pidFile, `${stranger.pid}\n1`);

				await reapTarget(opts(), target);

				assert.strictEqual(isAlive(stranger.pid), true, 'the reaper killed a node process running another script');
				assert.strictEqual(isAlive(sidecar.pid), false, 'and it must still stop the sidecar it recorded');
			} finally {
				stopQuietly(sidecar.pid);
				stopQuietly(stranger.pid);
			}
		});

		// A sidecar Harper spawned runs as Harper's user, as in processIdentity, whose rule this copy mirrors
		it("on Linux, a lock naming another user's process is not this sidecar, and is left alone", async function () {
			if (process.platform === 'win32') this.skip();
			const stranger = spawnOwnBinary({ unref: true });
			const recorded = spawnOwnBinary({ unref: true });
			try {
				await waitFor(() => isAlive(stranger.pid) && isAlive(recorded.pid));
				const target = writeTarget('agent', recorded.pid, process.execPath);
				writeFileSync(target.pidFile, `${stranger.pid}\n1`);
				const logFile = join(dir, 'reaper.log');

				const { signals } = await asAnotherUser({ pid: stranger.pid, kill: 'EPERM' }, () =>
					reapTarget(opts({ logFile }), target)
				);

				assert.deepStrictEqual(signals, [], "the reaper signalled another user's process");
				assert.match(
					readFileSync(logFile, 'utf-8'),
					new RegExp(`pid ${stranger.pid} is not this sidecar \\(differs\\)`)
				);
			} finally {
				stopQuietly(stranger.pid);
				stopQuietly(recorded.pid);
			}
		});

		it('a sidecar that ignores SIGTERM is escalated to SIGKILL', async () => {
			const readyFile = join(dir, 'stubborn-ready');
			const child = spawnStubborn(readyFile);
			try {
				// The SIGTERM handler must be installed, or a still-booting child dies without the escalation
				await waitFor(() => existsSync(readyFile));
				const target = writeTarget('agent', child.pid, process.execPath);
				await reapTarget(opts(), target);
				// Polled, since SIGKILL delivery and the zombie reap are asynchronous
				await waitFor(() => !isAlive(child.pid), { timeout: 2000, message: 'the SIGKILL escalation did not land' });
			} finally {
				stopQuietly(child.pid);
			}
		});
	});

	describe('run', () => {
		it('a replacement inside the grace window keeps the sidecars for it to adopt', async () => {
			const watched = spawnOwnBinary({ unref: true });
			const child = spawnOwnBinary({ unref: true });
			const replacement = spawnOwnBinary({ unref: true });
			try {
				await waitFor(() => isAlive(watched.pid) && isAlive(child.pid) && isAlive(replacement.pid));
				const target = writeTarget('agent', child.pid, process.execPath);
				// `harper restart` forks a replacement that adopts the children, so they must survive
				const hdbPidFile = join(dir, 'hdb.pid');
				writeFileSync(hdbPidFile, String(replacement.pid));

				const done = run(opts({ harperPid: watched.pid, hdbPidFile, restartGraceMs: 3000 }));
				process.kill(watched.pid, 'SIGKILL');
				await done;

				assert.strictEqual(isAlive(child.pid), true, 'the sidecar was reaped despite a replacement taking over');
				assert.strictEqual(existsSync(target.pidFile), true, 'and its lock must survive for the adoption');
			} finally {
				stopQuietly(watched.pid);
				stopQuietly(child.pid);
				stopQuietly(replacement.pid);
			}
		});

		it('no replacement inside the window means the sidecars are stopped', async () => {
			const watched = spawnOwnBinary({ unref: true });
			const child = spawnOwnBinary({ unref: true });
			try {
				await waitFor(() => isAlive(watched.pid) && isAlive(child.pid));
				writeTarget('agent', child.pid, process.execPath);

				const done = run(opts({ harperPid: watched.pid, hdbPidFile: join(dir, 'hdb.pid'), restartGraceMs: 200 }));
				process.kill(watched.pid, 'SIGKILL');
				await done;

				assert.strictEqual(isAlive(child.pid), false);
			} finally {
				stopQuietly(watched.pid);
				stopQuietly(child.pid);
			}
		});

		it('a sidecar recorded after the reaper started watching is still reaped', async () => {
			const watched = spawnOwnBinary({ unref: true });
			const child = spawnOwnBinary({ unref: true });
			try {
				await waitFor(() => isAlive(watched.pid) && isAlive(child.pid));
				// Empty when the watch begins: targets are read at reap time, so late sidecars are covered
				const done = run(opts({ harperPid: watched.pid, restartGraceMs: 200 }));
				writeTarget('late-agent', child.pid, process.execPath);
				process.kill(watched.pid, 'SIGKILL');
				await done;

				assert.strictEqual(isAlive(child.pid), false, 'a late-recorded sidecar was left running');
			} finally {
				stopQuietly(watched.pid);
				stopQuietly(child.pid);
			}
		});

		it('NEGATIVE: nothing is stopped while the watched process is still alive', async () => {
			const watched = spawnOwnBinary({ unref: true });
			const child = spawnOwnBinary({ unref: true });
			try {
				await waitFor(() => isAlive(watched.pid) && isAlive(child.pid));
				const target = writeTarget('agent', child.pid, process.execPath);

				const done = run(opts({ harperPid: watched.pid, restartGraceMs: 50 }));
				// Long enough to have polled several times and reaped if it were going to
				await new Promise((resolve) => setTimeout(resolve, 10 * POLL_MS));
				assert.strictEqual(isAlive(child.pid), true, 'the reaper fired while the node it watches was alive');
				assert.strictEqual(existsSync(target.pidFile), true);

				process.kill(watched.pid, 'SIGKILL');
				await done;
			} finally {
				stopQuietly(watched.pid);
				stopQuietly(child.pid);
			}
		});

		it('a stale hdb.pid does not pass for a replacement', async () => {
			const watched = spawnOwnBinary({ unref: true });
			const child = spawnOwnBinary({ unref: true });
			try {
				await waitFor(() => isAlive(watched.pid) && isAlive(child.pid));
				writeTarget('agent', child.pid, process.execPath);
				// Left by a node that is gone, so it must not read as a live replacement
				const hdbPidFile = join(dir, 'hdb.pid');
				writeFileSync(hdbPidFile, String(DEAD_PID));

				const done = run(opts({ harperPid: watched.pid, hdbPidFile, restartGraceMs: 200 }));
				process.kill(watched.pid, 'SIGKILL');
				await done;

				assert.strictEqual(isAlive(child.pid), false, 'a dead pid in hdb.pid was accepted as a replacement');
			} finally {
				stopQuietly(watched.pid);
				stopQuietly(child.pid);
			}
		});

		it('a lock naming a process that is already gone is not an error', async () => {
			const watched = spawnOwnBinary({ unref: true });
			try {
				await waitFor(() => isAlive(watched.pid));
				const target = writeTarget('agent', DEAD_PID, process.execPath);

				const done = run(opts({ harperPid: watched.pid, restartGraceMs: 50 }));
				process.kill(watched.pid, 'SIGKILL');
				await done;

				assert.strictEqual(existsSync(target.pidFile), false, 'the stale lock survived the reaping');
				assert.strictEqual(existsSync(join(dir, 'agent.sidecar.json')), false);
			} finally {
				stopQuietly(watched.pid);
			}
		});

		// A node restarted since may have taken the lock for a newer reaper, and a keeper releases its own
		it('removes its own lock only while it names this reaper with no keeper', async () => {
			const selfPidFile = join(dir, 'harper-sidecar-reaper.pid');
			const keeperRecord = JSON.stringify({ token: 't', keeper: DEAD_PID - 1, keeperArgv: [process.execPath] });
			for (const [lock, kept] of [
				[`${DEAD_PID - 2}\n1`, true],
				[`${process.pid}\n1\n${keeperRecord}\n`, true],
				[`${process.pid}\n1`, false],
			]) {
				const watched = spawnOwnBinary({ unref: true });
				try {
					await waitFor(() => isAlive(watched.pid));
					writeFileSync(selfPidFile, lock);
					const done = run(opts({ harperPid: watched.pid, restartGraceMs: 50, selfPidFile }));
					process.kill(watched.pid, 'SIGKILL');
					await done;
					if (kept)
						assert.strictEqual(readFileSync(selfPidFile, 'utf-8'), lock, 'a lock not this reaper`s was removed');
					else assert.strictEqual(existsSync(selfPidFile), false, 'this reaper left its own lock behind');
				} finally {
					stopQuietly(watched.pid);
				}
			}
		});

		it('NEGATIVE: a Harper running as pid 1 is not read as dead', () => {
			// A containerized Harper IS pid 1; only 0 and negatives are kill(2) group selectors
			assert.strictEqual(isAlive(1), true, 'pid 1 was read as dead, which reaps a containerized node on sight');
			assert.strictEqual(isAlive(0), false, '0 is the caller process group');
			assert.strictEqual(isAlive(-1), false, 'a negative is group -n');
		});
	});

	describe('parseArgs', () => {
		it('parses every flag and defaults the grace window', () => {
			const parsed = parseArgs([
				'--harper-pid',
				'7',
				'--pid-dir',
				'/x/pids',
				'--hdb-pid-file',
				'/x/hdb.pid',
				'--restart-grace-ms',
				'900',
				'--self-pid-file',
				'/x/pids/harper-sidecar-reaper.pid',
				'--log',
				'/x/log/sidecarReaper.log',
			]);
			assert.deepStrictEqual(parsed, {
				harperPid: 7,
				pidDir: '/x/pids',
				hdbPidFile: '/x/hdb.pid',
				restartGraceMs: 900,
				selfPidFile: '/x/pids/harper-sidecar-reaper.pid',
				logFile: '/x/log/sidecarReaper.log',
			});
			assert.strictEqual(parseArgs(['--harper-pid', '7']).restartGraceMs, 8000);
		});

		it('a flag arriving as the final token has nothing to consume and is dropped', () => {
			const parsed = parseArgs(['--harper-pid', '7', '--pid-dir']);
			assert.strictEqual(parsed.harperPid, 7);
			assert.strictEqual(parsed.pidDir, '');
		});
	});

	describe('spawned by path', () => {
		let stops = [];
		// Here rather than in the test's finally, which a test that timed out reaches only once its wait gives up
		afterEach(() => {
			for (const stop of stops) stop();
			stops = [];
		});

		it('orphans die when the parent dies mid-startup', async function () {
			if (process.platform === 'win32') this.skip();
			// The parent is SIGKILLed before any shutdown hook exists, and its recorded sidecar must still stop
			const reaperPath = REAPER_SCRIPT;
			const parentScript = `
				const { spawn } = require('node:child_process');
				const { writeFileSync } = require('node:fs');
				const { join } = require('node:path');
				const [pidDir, reaperPath, hdbPidFile] = process.argv.slice(1);
				const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1 << 30)'], { detached: true, stdio: 'ignore' });
				child.unref();
				writeFileSync(join(pidDir, 'mid-agent.pid'), child.pid + '\\n1');
				writeFileSync(join(pidDir, 'mid-agent.sidecar.json'), JSON.stringify({
					name: 'mid-agent', pidFile: join(pidDir, 'mid-agent.pid'), pid: child.pid, command: process.execPath,
				}));
				const reaper = spawn(process.execPath, [reaperPath,
					'--harper-pid', String(process.pid), '--pid-dir', pidDir, '--hdb-pid-file', hdbPidFile,
					'--restart-grace-ms', '200', '--self-pid-file', join(pidDir, 'harper-sidecar-reaper.pid'),
				], { detached: true, stdio: 'ignore' });
				reaper.unref();
				console.log(JSON.stringify({ child: child.pid, reaper: reaper.pid }));
				setInterval(() => {}, 1 << 30);
			`;
			const parent = spawn(process.execPath, ['-e', parentScript, dir, reaperPath, join(dir, 'hdb.pid')], {
				stdio: ['ignore', 'pipe', 'ignore'],
			});
			stops.push(() => stopQuietly(parent.pid));
			let pids;
			try {
				const line = await new Promise((resolve, reject) => {
					let out = '';
					parent.stdout.on('data', (chunk) => {
						out += chunk;
						if (out.includes('\n')) resolve(out);
					});
					parent.on('error', reject);
					parent.on('exit', () => resolve(out));
				});
				pids = JSON.parse(line);
				// Its grandchildren, which the parent's death leaves under pid 1
				track(pids.child);
				track(pids.reaper);
				stops.push(() => [pids.child, pids.reaper].forEach(stopQuietly));
				await waitFor(() => isAlive(pids.child) && isAlive(pids.reaper));

				process.kill(parent.pid, 'SIGKILL');

				await waitFor(() => !isAlive(pids.child), { timeout: 15000, interval: 100 });
				await waitFor(() => !existsSync(join(dir, 'mid-agent.sidecar.json')), { timeout: 5000, interval: 100 });
				assert.strictEqual(existsSync(join(dir, 'mid-agent.pid')), false);
				await waitFor(() => !existsSync(join(dir, 'harper-sidecar-reaper.pid')), { timeout: 5000, interval: 100 });
			} finally {
				stopQuietly(parent.pid);
				if (pids) {
					stopQuietly(pids.child);
					stopQuietly(pids.reaper);
				}
			}
		});
	});
});

// The fork is by path under a bare node, so nothing type-checks this string; a stale one builds clean
describe('the reaper script path', () => {
	it('names a file that is actually there', () => {
		assert.ok(
			existsSync(REAPER_SCRIPT),
			`sidecarLifecycle forks ${REAPER_SCRIPT}, and nothing is at that path. A move that missed the literal builds clean and fails as a duplicate reaper.`
		);
	});

	it('resolves inside the module folder, so a move cannot leave it behind', () => {
		assert.match(REAPER_SCRIPT, /[\\/]security[\\/]processSupervisor[\\/]sidecarReaper\.js$/);
	});
});
