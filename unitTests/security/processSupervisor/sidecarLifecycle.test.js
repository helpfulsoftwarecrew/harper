'use strict';

// The sidecar lifecycle behind scope.processes: the PID-locked spawn (start, join,
// adopt-on-unidentified-version-change), configs, and verify.

const assert = require('node:assert');
const { execFileSync, spawn } = require('node:child_process');
const { setTimeout: sleep } = require('node:timers/promises');
const { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');

const { waitFor } = require('../../waitFor.js');
const { TEST_TIMING, collectingLogger } = require('./helpers.js');
const { LONG_RUNNING, failOnSurvivors, reapPidDir, runningWith, stopQuietly } = require('./reap.js');
const env = require('#src/utility/environment/environmentManager');
const terms = require('#src/utility/hdbTerms');
const {
	isProcessAlive,
	parentOf,
	platformCanIdentifyProcesses,
	startedAt,
} = require('#src/security/processSupervisor/processIdentity');
const {
	_setLostCommitGraceForTests,
	child_processConstrained,
	spawnKept,
} = require('#src/security/processSupervisor/constrainedChildProcess');
const { _setPollIntervalForTests } = require('#src/security/processSupervisor/adoptionWrapper');
const {
	_setIdentifyDeadlineForTests,
	acquirePidFileLockAsync,
	readPidLock,
} = require('#src/security/processSupervisor/pidFileLock');
const {
	REAPER_NAME,
	SidecarProcesses,
	_setTimingForTests,
	fingerprintVersion,
	nextReaperAttempt,
} = require('#src/security/processSupervisor/sidecarLifecycle');

// The caps below end on their condition
const POLL_MS = 25;
/** SIGTERM, which a live owner reads as a deliberate stop; SIGKILL reads as a crash, and the owner respawns it. */
const AS_A_STOP = { signal: 'SIGTERM' };
const JOINER_NOTICE_MS = 6000;
/** Ten first backoffs: long enough that a joiner that decided to restart has. */
const RESPAWN_SETTLE_MS = 10 * TEST_TIMING.respawnBaseMs;

/** Shortens this describe's waits, and puts back the shipped values after it. */
function useTestTiming() {
	before(() => {
		_setPollIntervalForTests(POLL_MS);
		_setIdentifyDeadlineForTests(25);
		_setTimingForTests(TEST_TIMING);
	});
	after(() => {
		_setPollIntervalForTests();
		_setIdentifyDeadlineForTests();
		_setTimingForTests();
	});
}

/**
 * Supervisors that refuse to start anything once `end` has SIGTERMed what their states name, so a timer that outlives
 * its test starts nothing. `keep: null` is the path with no keeper, which Windows takes.
 */
function supervisors() {
	const made = [];
	let open = true;
	const whileOpen =
		(start) =>
		(...args) => {
			if (!open) throw new Error('the test that owned this supervisor has ended');
			return start(...args);
		};
	return {
		make(logger, { keep = whileOpen(spawnKept) } = {}) {
			const processes = new SidecarProcesses(
				logger,
				whileOpen(child_processConstrained.spawn),
				whileOpen(child_processConstrained.fork),
				keep
			);
			made.push(processes);
			return processes;
		},
		end() {
			open = false;
			for (const processes of made) {
				for (const state of [...processes.states, processes.reaper]) stopQuietly(state?.pid, AS_A_STOP);
			}
		},
	};
}

describe('sidecarLifecycle', function () {
	failOnSurvivors();
	useTestTiming();
	this.timeout(20000);
	let pidDir;
	let supervised;

	beforeEach(() => {
		pidDir = join(env.getHdbBasePath(), 'pids');
		// The locks and descriptors are the only record of what this test started, so reap before removing them
		reapPidDir(pidDir);
		rmSync(pidDir, { recursive: true, force: true });
		supervised = supervisors();
	});

	afterEach(() => {
		supervised.end();
		// The locks and descriptors are the only record of what this test started, so reap before removing them
		reapPidDir(pidDir);
		rmSync(pidDir, { recursive: true, force: true });
	});

	it('ships the timing this suite shortens', () => {
		try {
			assert.deepStrictEqual(_setTimingForTests(), {
				respawnBaseMs: 1000,
				rejoinPollMs: 250,
				rejoinGraceMs: 15_000,
				keeperStartMs: 15_000,
			});
		} finally {
			_setTimingForTests(TEST_TIMING);
		}
	});

	describe('fingerprintVersion', () => {
		it('is a number inside 2^31, stable, and moved by any input', () => {
			const version = fingerprintVersion('config', 'key');
			assert.strictEqual(version, fingerprintVersion('config', 'key'));
			assert.ok(Number.isInteger(version) && version >= 0 && version < 2 ** 31);
			assert.notStrictEqual(version, fingerprintVersion('config', 'other'));
		});
	});

	// The lock's own verdicts on an existing lock are asserted in pidFileLock.test.js, where they are decided

	describe('SidecarProcesses.start', () => {
		it('starts through the PID lock, writes configs atomically, verifies, and a second start joins', async () => {
			const configPath = join(env.getHdbBasePath(), 'sidecar-config', 'agent.yaml');
			rmSync(join(env.getHdbBasePath(), 'sidecar-config'), { recursive: true, force: true });
			const logger = collectingLogger();
			const descriptor = {
				name: 'sidecar-lifecycle-test',
				command: 'node',
				args: ['-e', LONG_RUNNING],
				fingerprint: ['config-v1'],
				configFiles: { [configPath]: 'listen: 9000\n' },
				verify: async (state) => ({ ok: state.started, detail: `pid ${state.pid}` }),
			};

			// The default constructor, so the constrained spawn a component is handed stays the one under test
			const first = await new SidecarProcesses(logger).start(descriptor);
			try {
				assert.strictEqual(first.started, true);
				assert.strictEqual(first.adopted, false, 'the winner started the process, not joined one');
				assert.ok(Number.isInteger(first.pid));
				assert.strictEqual(readFileSync(configPath, 'utf-8'), 'listen: 9000\n');
				assert.strictEqual(first.verified, true);
				assert.strictEqual(first.verifyDetail, `pid ${first.pid}`);
				assert.ok(logger.lines.info.some((line) => line.includes('started the sidecar-lifecycle-test')));

				// A second start of the same descriptor must join the running process, not start a second one
				const second = await supervised.make(collectingLogger()).start(descriptor);
				assert.strictEqual(second.adopted, true);
				assert.strictEqual(second.pid, first.pid);
			} finally {
				stopQuietly(first.pid, AS_A_STOP);
				rmSync(join(env.getHdbBasePath(), 'sidecar-config'), { recursive: true, force: true });
			}
		});

		it('records which pid the verdict describes, stamped before the proof runs', async () => {
			const logger = collectingLogger();
			// Stamped before the await, or a restart during a slow verify would record the pid that replaced it
			let stampedDuringProof;
			const first = await supervised.make(logger).start({
				name: 'sidecar-verified-pid-test',
				command: 'node',
				args: ['-e', LONG_RUNNING],
				verify: async (state) => {
					stampedDuringProof = state.verifiedPid;
					return { ok: true, detail: 'up' };
				},
			});
			try {
				assert.strictEqual(stampedDuringProof, first.pid, 'the pid was stamped after the proof, not before');
				assert.strictEqual(first.verifiedPid, first.pid);
			} finally {
				stopQuietly(first.pid, AS_A_STOP);
			}
		});

		// The supervisor rewrites `pid` on one object for the node's life, so a verdict left standing through a
		// restart is a dead process vouching for the live one.
		it('clears the previous verdict when a restart begins its own proof', async function () {
			if (process.platform === 'win32') this.skip();
			const reasons = [];
			let releaseSecondProof;
			const state = await supervised.make(collectingLogger()).start({
				name: 'sidecar-verdict-window-test',
				command: 'node',
				args: ['-e', LONG_RUNNING],
				reaper: false,
				verify: (_state, context) => {
					reasons.push(context.reason);
					if (reasons.length === 1) return Promise.resolve({ ok: true, detail: 'first' });
					return new Promise((resolve) => {
						releaseSecondProof = () => resolve({ ok: true, detail: 'second' });
					});
				},
			});
			try {
				const died = state.pid;
				assert.strictEqual(state.verified, true);
				process.kill(died, 'SIGKILL');
				await waitFor(() => releaseSecondProof !== undefined, {
					timeout: 15000,
					interval: 50,
					message: 'the restart never began a proof of its own',
				});
				assert.notStrictEqual(state.pid, died);
				assert.strictEqual(state.verifiedPid, state.pid);
				assert.strictEqual(state.verified, undefined, "the dead process's verdict stood beside the new pid");
				assert.strictEqual(state.verifyDetail, undefined);
				releaseSecondProof();
				await waitFor(() => state.verified === true, { timeout: 5000, interval: 20 });
				assert.strictEqual(state.verifyDetail, 'second');
				assert.deepStrictEqual(reasons, ['untaken', 'restarted']);
			} finally {
				stopQuietly(state.pid, AS_A_STOP);
			}
		});

		it('NEGATIVE: a proof that outlives its process does not overwrite the verdict of the one that replaced it', async function () {
			if (process.platform === 'win32') this.skip();
			let proofs = 0;
			let releaseSecondProof;
			const state = await supervised.make(collectingLogger()).start({
				name: 'sidecar-stale-proof-test',
				command: 'node',
				args: ['-e', LONG_RUNNING],
				reaper: false,
				verify: () => {
					proofs += 1;
					if (proofs !== 2) return Promise.resolve({ ok: true, detail: `proof ${proofs}` });
					return new Promise((resolve) => {
						releaseSecondProof = () => resolve({ ok: false, detail: 'proof 2' });
					});
				},
			});
			try {
				process.kill(state.pid, 'SIGKILL');
				await waitFor(() => releaseSecondProof !== undefined, { timeout: 15000, interval: 50 });
				const second = state.pid;
				// The second process dies while its proof is still polling
				process.kill(second, 'SIGKILL');
				await waitFor(() => proofs === 3 && state.verified === true, {
					timeout: 15000,
					interval: 50,
					message: 'the third process was never proved',
				});
				const third = state.pid;
				assert.notStrictEqual(third, second);
				const takenAt = state.verifiedAt;
				releaseSecondProof();
				await sleep(50);
				assert.strictEqual(state.verified, true, "a refusal about a dead process replaced the live one's verdict");
				assert.strictEqual(state.verifyDetail, 'proof 3');
				assert.strictEqual(state.verifiedPid, third);
				assert.strictEqual(state.verifiedAt, takenAt);
			} finally {
				stopQuietly(state.pid, AS_A_STOP);
			}
		});

		it('NEGATIVE: a fingerprint change on an unidentifiable command no keeper records adopts rather than kills', async function () {
			// A bare allowlist name answers "cannot tell", so the mismatch adopts; Windows keeps the legacy restart
			if (!platformCanIdentifyProcesses()) this.skip();
			const logger = collectingLogger();
			const base = { name: 'sidecar-adopt-test', command: 'node', args: ['-e', LONG_RUNNING] };
			const first = await supervised.make(logger, { keep: null }).start({ ...base, fingerprint: ['config-v1'] });
			try {
				assert.strictEqual(first.started, true);
				const changed = await supervised
					.make(collectingLogger(), { keep: null })
					.start({ ...base, fingerprint: ['config-v2'] });
				assert.strictEqual(changed.adopted, true, 'an unidentified holder was replaced');
				assert.strictEqual(changed.pid, first.pid);
				assert.strictEqual(isProcessAlive(first.pid), true, 'an unidentified pid was signalled');
			} finally {
				stopQuietly(first.pid, AS_A_STOP);
			}
		});

		it('REGRESSION: with no keeper, a death with an owner present is restarted by the owner alone', async function () {
			if (process.platform === 'win32') this.skip();
			// The owner removes the lock on the exit event, before any joiner's poll sees the death
			const name = 'sidecar-owned-death-test';
			const descriptor = {
				name,
				command: 'node',
				args: ['-e', LONG_RUNNING],
				fingerprint: ['owned-v1'],
				reaper: false,
			};
			const ownerLog = collectingLogger();
			const joinerLogs = [collectingLogger(), collectingLogger()];
			const owner = await supervised.make(ownerLog, { keep: null }).start(descriptor);
			const joiners = [];
			try {
				assert.strictEqual(owner.adopted, false, 'the first start must hold the real child');
				// The shipped poll for the joiners: one landing between the death and the owner's unlink is the one race
				_setPollIntervalForTests();
				try {
					for (const logger of joinerLogs)
						joiners.push(await supervised.make(logger, { keep: null }).start(descriptor));
				} finally {
					_setPollIntervalForTests(POLL_MS);
				}
				for (const joiner of joiners) {
					assert.strictEqual(joiner.adopted, true, 'a second start began its own process');
					assert.strictEqual(joiner.pid, owner.pid);
				}

				// Killed straight after the joins, so their next poll is a full interval behind the owner's exit event
				const died = owner.pid;
				process.kill(died, 'SIGKILL');
				await waitFor(() => owner.pid !== died && isProcessAlive(owner.pid), {
					timeout: 15000,
					interval: 50,
					message: 'the owner never restarted the process it started',
				});
				assert.strictEqual(owner.restarts, 1);
				assert.strictEqual(owner.adopted, false, 'the owner must still hold a real child after the restart');

				// Each joiner logs exactly one line about the death, which is the signal that it has decided
				await waitFor(() => joinerLogs.every((log) => log.lines.warn.some((line) => line.includes('has died'))), {
					timeout: JOINER_NOTICE_MS,
					interval: 50,
					message: 'a joiner never noticed the death of the process it joined',
				});
				await sleep(RESPAWN_SETTLE_MS);
				for (const [index, joiner] of joiners.entries()) {
					assert.strictEqual(
						joiner.restarts,
						0,
						`joiner ${index} restarted a process its owner already restarts, which multiplies the capped backoff`
					);
					assert.ok(
						joinerLogs[index].lines.warn.some((line) => line.includes('no longer names it')),
						`joiner ${index} did not report the death as one its owner is handling`
					);
					assert.ok(
						!joinerLogs[index].lines.warn.some((line) => line.includes('claimed its PID lock')),
						`joiner ${index} claimed a lock the owner had already removed`
					);
				}
				assert.strictEqual(
					readFileSync(join(pidDir, `${name}.pid`), 'utf-8').split('\n')[0],
					String(owner.pid),
					'the lock must name the one process the owner restarted'
				);
			} finally {
				stopQuietly(owner.pid, AS_A_STOP);
			}
		});

		it('a fingerprint change replaces a bare-name process started under a keeper, which its start time identifies', async function () {
			if (!platformCanIdentifyProcesses()) this.skip();
			const base = { name: 'sidecar-kept-replace-test', command: 'node', args: ['-e', LONG_RUNNING], reaper: false };
			const first = await supervised.make(collectingLogger()).start({ ...base, fingerprint: ['config-v1'] });
			let changed;
			try {
				assert.strictEqual(first.started, true);
				changed = await supervised.make(collectingLogger()).start({ ...base, fingerprint: ['config-v2'] });
				assert.strictEqual(changed.adopted, false, 'the old configuration was joined rather than replaced');
				assert.notStrictEqual(changed.pid, first.pid);
				await waitFor(() => !isProcessAlive(first.pid), { message: 'the replaced process is still running' });
			} finally {
				stopQuietly(first.pid, AS_A_STOP);
				stopQuietly(changed?.pid, AS_A_STOP);
			}
		});

		it('REGRESSION: a death under a keeper is restarted by the keeper alone, and every thread joins that one process', async function () {
			if (process.platform === 'win32') this.skip();
			const name = 'sidecar-kept-death-test';
			// The name rides in the arguments, so the processes running it can be counted
			const descriptor = {
				name,
				command: 'node',
				args: ['-e', LONG_RUNNING, name],
				fingerprint: ['kept-v1'],
				reaper: false,
			};
			const logs = [collectingLogger(), collectingLogger(), collectingLogger()];
			const states = [];
			for (const logger of logs) states.push(await supervised.make(logger).start(descriptor));
			const died = states[0].pid;
			try {
				assert.deepStrictEqual(
					states.map((state) => state.adopted),
					[false, true, true]
				);
				process.kill(died, 'SIGKILL');
				await waitFor(
					() => states.every((state) => state.pid !== died && state.pid === states[0].pid && isProcessAlive(state.pid)),
					{ timeout: 15000, interval: 50, message: 'the threads did not all end on one replacement' }
				);
				await sleep(RESPAWN_SETTLE_MS);
				const running = runningWith(name, { keepers: false });
				assert.deepStrictEqual(running, [states[0].pid], `more than one process runs ${name}: ${running}`);
				for (const [index, log] of logs.entries()) {
					assert.ok(
						!log.lines.warn.some((line) => line.includes('claimed its PID lock')),
						`thread ${index} claimed a death its keeper was answering`
					);
					assert.strictEqual(states[index].restarts, 1, `thread ${index} does not report the keeper's restart`);
				}
				assert.strictEqual(readFileSync(join(pidDir, `${name}.pid`), 'utf-8').split('\n')[0], String(states[0].pid));
			} finally {
				stopQuietly(states[0].pid, AS_A_STOP);
			}
		});

		it('three starts of an exec wrapper under a keeper run one process, which its start time identifies', async function () {
			if (!platformCanIdentifyProcesses()) this.skip();
			const name = 'sidecar-kept-wrapper-test';
			// A wrapper that execs another binary runs as that binary, which the command it was started by cannot identify
			const wrapper = join(env.getHdbBasePath(), `${name}.sh`);
			writeFileSync(wrapper, `#!/bin/sh\nexec '${process.execPath}' -e '${LONG_RUNNING}' ${name}\n`, { mode: 0o755 });
			const allowed = env.get(terms.CONFIG_PARAMS.APPLICATIONS_ALLOWEDSPAWNCOMMANDS);
			env.setProperty(terms.CONFIG_PARAMS.APPLICATIONS_ALLOWEDSPAWNCOMMANDS, [...allowed, wrapper]);
			const states = [];
			try {
				for (let index = 0; index < 3; index++) {
					states.push(
						await supervised
							.make(collectingLogger())
							.start({ name, command: wrapper, fingerprint: [name], reaper: false })
					);
				}
				const [first] = states;
				assert.deepStrictEqual(
					states.map((state) => state.pid),
					[first.pid, first.pid, first.pid],
					'a later start began an instance of its own'
				);
				assert.deepStrictEqual(
					runningWith(name, { keepers: false }),
					[first.pid],
					'more than one instance of the wrapper runs'
				);
			} finally {
				env.setProperty(terms.CONFIG_PARAMS.APPLICATIONS_ALLOWEDSPAWNCOMMANDS, allowed);
				for (const state of states) stopQuietly(state.pid, AS_A_STOP);
				rmSync(wrapper, { force: true });
			}
		});

		it('a keeper that gives up publishes the process as not running, with why', async function () {
			if (process.platform === 'win32') this.skip();
			const state = await supervised.make(collectingLogger()).start({
				name: 'sidecar-kept-gave-up-test',
				command: 'node',
				args: ['-e', 'process.exit(3)'],
				reaper: false,
			});
			await waitFor(() => state.error !== undefined && state.started === false, {
				timeout: 15000,
				interval: 50,
				message: 'a keeper past its cap was never reported',
			});
			assert.match(state.error, /has died 6 times \(exit code 3\); not restarting it again/);
			assert.strictEqual(state.pid, undefined, 'a process nothing will restart must not publish a pid');
			assert.strictEqual(
				existsSync(join(pidDir, 'sidecar-kept-gave-up-test.pid')),
				false,
				'the lock outlived the keeper'
			);
		});

		it('gives its claim back when the keeper names no pid in time, and reports why', async function () {
			if (process.platform === 'win32') this.skip();
			_setTimingForTests({ ...TEST_TIMING, keeperStartMs: 300 });
			const name = 'sidecar-kept-silent-test';
			const lockPath = join(pidDir, `${name}.pid`);
			// A claim taken as spawnKept takes it, with a launcher standing in for a keeper that never commits
			let launcher;
			const keep = async () => {
				const held = await acquirePidFileLockAsync(lockPath, 'node', undefined, undefined);
				launcher = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 5000)'], { stdio: 'ignore' });
				return { kind: 'launched', token: held.token, launcher, pidFilePath: lockPath };
			};
			try {
				const state = await supervised
					.make(collectingLogger(), { keep })
					.start({ name, command: 'node', args: ['-e', LONG_RUNNING], reaper: false });
				assert.strictEqual(state.started, false);
				assert.strictEqual(state.pid, undefined);
				assert.match(state.error, /its keeper named no pid within 300ms/);
				assert.strictEqual(existsSync(lockPath), false, 'a claim no keeper will commit was left holding the name');
			} finally {
				_setTimingForTests(TEST_TIMING);
				stopQuietly(launcher?.pid, AS_A_STOP);
			}
		});

		it('refuses a missing absolute binary before spawning', async () => {
			const logger = collectingLogger();
			const state = await supervised.make(logger).start({
				name: 'sidecar-missing-test',
				command: '/nonexistent/sidecar-binary',
			});
			assert.strictEqual(state.started, false);
			assert.match(state.error, /missing/);
			assert.strictEqual(existsSync(join(pidDir, 'sidecar-missing-test.pid')), false, 'no lock for a refused spawn');
		});

		it('reports an allowlist refusal with the path to allowlist', async function () {
			if (process.platform === 'win32') this.skip();
			const logger = collectingLogger();
			const state = await supervised.make(logger).start({
				name: 'sidecar-refused-test',
				command: '/bin/sleep',
				args: ['600'],
			});
			assert.strictEqual(state.started, false);
			assert.match(state.error, /not allowed/);
			assert.ok(logger.lines.error.some((line) => line.includes('allowedSpawnCommands')));
		});

		it('requires a name and a command deterministically', async () => {
			await assert.rejects(new SidecarProcesses(collectingLogger()).start({ command: 'node' }), TypeError);
			await assert.rejects(new SidecarProcesses(collectingLogger()).start({ name: 'x' }), TypeError);
		});

		it('NEGATIVE: refuses the reaper`s own name by any spelling of its lock, and a name that is not one file name', async () => {
			// The name is a file name under pids/, and darwin's file system folds case
			const spellings = [REAPER_NAME, REAPER_NAME.toUpperCase(), `./${REAPER_NAME}`, `x/../${REAPER_NAME}`];
			for (const name of [...spellings, '..', 'a/b', '']) {
				await assert.rejects(
					supervised.make(collectingLogger()).start({ name, command: 'node', args: ['-e', LONG_RUNNING] }),
					TypeError,
					`the name ${JSON.stringify(name)} was accepted`
				);
			}
			assert.strictEqual(
				existsSync(join(pidDir, `${REAPER_NAME}.pid`)),
				false,
				'a refused start took the reaper`s lock'
			);
		});

		it('with no keeper, a spawn that yields no pid is reported not started, with its error, and frees the name', async function () {
			if (process.platform === 'win32') this.skip();
			// Allowed, and not on PATH, so the spawn returns a child with no pid and an 'error' rather than throwing
			const command = `harper-no-such-sidecar-${process.pid}`;
			const allowed = env.get(terms.CONFIG_PARAMS.APPLICATIONS_ALLOWEDSPAWNCOMMANDS);
			env.setProperty(terms.CONFIG_PARAMS.APPLICATIONS_ALLOWEDSPAWNCOMMANDS, [...allowed, command]);
			let verified = 0;
			try {
				const processes = supervised.make(collectingLogger(), { keep: null });
				const descriptor = {
					name: 'sidecar-owner-no-pid-test',
					command,
					verify: async () => {
						verified++;
						return { ok: true };
					},
				};
				const state = await processes.start(descriptor);
				assert.strictEqual(state.started, false, 'a spawn that never ran is reported started');
				assert.strictEqual(state.pid, undefined);
				assert.match(state.error ?? '', /ENOENT|EACCES/, 'the spawn`s error is not on the state');
				assert.strictEqual(verified, 0, 'a process that never ran was verified');
				assert.strictEqual(processes.reaper, undefined, 'a reaper was launched for a process that never ran');
				assert.strictEqual(existsSync(join(pidDir, `${descriptor.name}.pid`)), false, 'the failed spawn kept the name');
				// The name is free, so the next start tries again rather than joining nothing
				const again = await processes.start(descriptor);
				assert.strictEqual(again.adopted, undefined, 'the next start joined a process that never ran');
				assert.match(again.error ?? '', /ENOENT|EACCES/);
			} finally {
				env.setProperty(terms.CONFIG_PARAMS.APPLICATIONS_ALLOWEDSPAWNCOMMANDS, allowed);
			}
		});

		// The owner holds the child and its exit status, so it clears the state as a thread under a keeper does
		for (const [how, stop] of [
			['a SIGTERM', (pid) => process.kill(pid, 'SIGTERM')],
			['a clean exit', (pid) => process.kill(pid, 'SIGUSR2')],
		]) {
			it(`with no keeper, an owner reports ${how} as nothing running, with no pid and no verdict`, async function () {
				if (process.platform === 'win32') this.skip();
				// The child marks itself ready once its handler holds, or an early SIGUSR2 would kill it as a crash
				const ready = join(env.getHdbBasePath(), `sidecar-owner-stop-${Date.now()}.ready`);
				const state = await supervised.make(collectingLogger(), { keep: null }).start({
					name: 'sidecar-owner-stop-test',
					command: 'node',
					args: [
						'-e',
						`process.on('SIGUSR2', () => process.exit(0)); require('node:fs').writeFileSync(process.argv[1], ''); ${LONG_RUNNING}`,
						ready,
					],
					reaper: false,
					verify: async () => ({ ok: true }),
				});
				try {
					assert.strictEqual(state.verified, true);
					await waitFor(() => existsSync(ready), { message: 'the child never became ready' });
					stop(state.pid);
					await waitFor(() => state.exited === true, { timeout: 5000, message: 'the owner never saw the stop' });
					assert.strictEqual(state.started, false, 'a stopped process is still reported started');
					assert.strictEqual(state.pid, undefined, 'the stopped pid is still published');
					assert.strictEqual(state.verified, undefined, 'the stopped process still reads verified');
					assert.strictEqual(state.verifiedPid, undefined);
					assert.strictEqual(state.verifiedAt, undefined, 'a verdict that is gone still has a time');
				} finally {
					rmSync(ready, { force: true });
				}
			});
		}

		it('with no keeper, an owner that gives up reports nothing running and counts every death', async function () {
			if (process.platform === 'win32') this.skip();
			const state = await supervised.make(collectingLogger(), { keep: null }).start({
				name: 'sidecar-owner-gave-up-test',
				command: 'node',
				args: ['-e', 'setTimeout(() => process.exit(3), 100)'],
				reaper: false,
				verify: async () => ({ ok: true }),
			});
			await waitFor(() => state.error !== undefined, {
				timeout: 15000,
				interval: 50,
				message: 'an owner past its cap never reported',
			});
			assert.match(state.error, /has died 6 times \(exit code 3\); not restarting it again/);
			assert.strictEqual(state.started, false);
			assert.strictEqual(state.pid, undefined, 'a process nothing will restart must not publish a pid');
			assert.strictEqual(state.verified, undefined);
		});

		it('joins a sibling that starts the name after this thread gave its claim back', async function () {
			if (process.platform === 'win32') this.skip();
			_setTimingForTests({ ...TEST_TIMING, keeperStartMs: 300 });
			const name = 'sidecar-kept-gave-back-test';
			const lockPath = join(pidDir, `${name}.pid`);
			const other = spawn(process.execPath, ['-e', LONG_RUNNING], { stdio: 'ignore' });
			let launcher;
			let calls = 0;
			// The first start's keeper never commits; any later start is the real one
			const keep = async (command, args, options) => {
				if (++calls > 1) return spawnKept(command, args, options);
				const held = await acquirePidFileLockAsync(lockPath, 'node', undefined, undefined);
				launcher = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 5000)'], { stdio: 'ignore' });
				return { kind: 'launched', token: held.token, launcher, pidFilePath: lockPath };
			};
			try {
				await waitFor(() => isProcessAlive(other.pid));
				const state = await supervised
					.make(collectingLogger(), { keep })
					.start({ name, command: 'node', args: ['-e', LONG_RUNNING], reaper: false });
				assert.strictEqual(state.started, false);
				assert.strictEqual(existsSync(lockPath), false, 'the claim was not given back');
				// A sibling starts the name the claim left free
				writeFileSync(lockPath, `${other.pid}`);
				await waitFor(() => state.pid === other.pid, {
					timeout: 5000,
					message: `the thread that gave its claim back reports ${JSON.stringify(state)}`,
				});
				assert.strictEqual(state.adopted, true);
			} finally {
				_setTimingForTests(TEST_TIMING);
				stopQuietly(launcher?.pid, AS_A_STOP);
				stopQuietly(other.pid, AS_A_STOP);
			}
		});

		it('joins what holds the lock when its keeper lost the lock, which leaves no record of the death', async function () {
			if (process.platform === 'win32') this.skip();
			const name = 'sidecar-kept-lock-taken-test';
			const lockPath = join(pidDir, `${name}.pid`);
			const version = fingerprintVersion(name);
			const other = spawn(process.execPath, ['-e', LONG_RUNNING], { stdio: 'ignore' });
			try {
				await waitFor(() => isProcessAlive(other.pid));
				const state = await supervised
					.make(collectingLogger())
					.start({ name, command: 'node', args: ['-e', LONG_RUNNING], fingerprint: [name], reaper: false });
				assert.strictEqual(state.started, true);
				const kept = readPidLock(lockPath);
				// Another holder takes the lock, and the keeper that held it then loses its process
				const taker = JSON.stringify({ token: 'another-claim', host: process.pid });
				writeFileSync(lockPath, `${other.pid}\n${version}\n${taker}\n`);
				process.kill(kept.pid, 'SIGKILL');
				await waitFor(() => state.pid === other.pid, {
					timeout: 10000,
					message: `the thread whose keeper lost the lock reports ${JSON.stringify(state)}`,
				});
				assert.strictEqual(state.adopted, true);
				assert.strictEqual(existsSync(`${lockPath}.exit`), false, 'the keeper that lost its lock wrote a record');
			} finally {
				stopQuietly(other.pid, AS_A_STOP);
			}
		});

		// A claim another thread took is that thread's start, so this one joins it rather than reporting a failure
		it('joins the process of a thread that took its claim over, rather than reporting a failed start', async function () {
			if (process.platform === 'win32') this.skip();
			const name = 'sidecar-kept-taken-over-test';
			const lockPath = join(pidDir, `${name}.pid`);
			const version = fingerprintVersion(name);
			const other = spawn(process.execPath, ['-e', LONG_RUNNING], { stdio: 'ignore' });
			let calls = 0;
			// The first start's claim is taken over by another holder at once; any later start is the real one
			const keep = async (command, args, options) => {
				if (++calls > 1) return spawnKept(command, args, options);
				const held = await acquirePidFileLockAsync(lockPath, 'node', undefined, version);
				writeFileSync(lockPath, `${other.pid}\n${version}`);
				const launcher = spawn(process.execPath, ['-e', ''], { stdio: 'ignore' });
				return { kind: 'launched', token: held.token, launcher, pidFilePath: lockPath };
			};
			try {
				await waitFor(() => isProcessAlive(other.pid));
				const state = await supervised
					.make(collectingLogger(), { keep })
					.start({ name, command: 'node', args: ['-e', LONG_RUNNING], fingerprint: [name], reaper: false });
				await waitFor(() => state.pid === other.pid, {
					timeout: 5000,
					message: `the thread whose claim was taken reports ${JSON.stringify(state)}`,
				});
				assert.strictEqual(state.started, true);
				assert.strictEqual(state.adopted, true, 'a thread whose claim was taken started a process of its own');
			} finally {
				stopQuietly(other.pid, AS_A_STOP);
			}
		});
	});

	describe('the constrained spawn', () => {
		it('gives the name back when a spawn yields no pid, so the next spawn of it waits for nothing', async function () {
			if (process.platform === 'win32') this.skip();
			const missing = join(env.getHdbBasePath(), 'no-such-sidecar-binary');
			const allowed = env.get(terms.CONFIG_PARAMS.APPLICATIONS_ALLOWEDSPAWNCOMMANDS);
			env.setProperty(terms.CONFIG_PARAMS.APPLICATIONS_ALLOWEDSPAWNCOMMANDS, [...allowed, missing]);
			try {
				const child = child_processConstrained.spawn(missing, [], { name: 'constrained-no-pid-test', stdio: 'ignore' });
				const failed = new Promise((resolve) => child.once('error', resolve));
				assert.strictEqual(child.pid, undefined);
				assert.strictEqual(
					existsSync(join(pidDir, 'constrained-no-pid-test.pid')),
					false,
					'a spawn that never ran kept its name'
				);
				assert.strictEqual((await failed).code, 'ENOENT');
			} finally {
				env.setProperty(terms.CONFIG_PARAMS.APPLICATIONS_ALLOWEDSPAWNCOMMANDS, allowed);
			}
		});
	});

	describe('the constrained spawn, losing its commit', () => {
		it('NEGATIVE: stops the child it could not name, with SIGKILL once SIGTERM has had its grace', async function () {
			if (process.platform === 'win32') this.skip();
			this.timeout(20000);
			const name = 'constrained-lost-commit-test';
			const lockPath = join(pidDir, `${name}.pid`);
			const gate = `${lockPath}.claiming`;
			const marker = `lost-commit-${process.pid}-${Date.now()}`;
			mkdirSync(pidDir, { recursive: true });
			// A live holder of the gate that lets go after a while, so the commit waits while the child sets its trap
			const holder = spawn('/bin/sh', ['-c', `sleep 0.5; rm -f "${gate}"`], { stdio: 'ignore' });
			const allowed = env.get(terms.CONFIG_PARAMS.APPLICATIONS_ALLOWEDSPAWNCOMMANDS);
			env.setProperty(terms.CONFIG_PARAMS.APPLICATIONS_ALLOWEDSPAWNCOMMANDS, [...allowed, '/bin/sh']);
			assert.strictEqual(_setLostCommitGraceForTests(), 5000, 'the shipped grace');
			_setLostCommitGraceForTests(300);
			try {
				await waitFor(() => isProcessAlive(holder.pid) && startedAt(holder.pid) !== null);
				const holding = `${holder.pid}\n${startedAt(holder.pid)}\nholder`;
				// Read inside the spawn, after the claim: the lock goes and the gate is held, so the commit finds it gone
				const options = {
					name,
					get stdio() {
						rmSync(lockPath, { force: true });
						writeFileSync(gate, holding);
						return 'ignore';
					},
				};
				assert.throws(
					() =>
						child_processConstrained.spawn(
							'/bin/sh',
							['-c', 'trap "" TERM; while :; do sleep 1; done', marker],
							options
						),
					/could not name the process just started \(gone\)/
				);
				assert.strictEqual(
					runningWith(marker, { keepers: false }).length,
					1,
					'the child did not outlive its SIGTERM, so nothing escalated'
				);
				await waitFor(() => runningWith(marker, { keepers: false }).length === 0, {
					timeout: 10000,
					interval: 50,
					message: 'a child no lock names outlived its SIGTERM for good',
				});
			} finally {
				_setLostCommitGraceForTests();
				env.setProperty(terms.CONFIG_PARAMS.APPLICATIONS_ALLOWEDSPAWNCOMMANDS, allowed);
				for (const pid of runningWith(marker, { keepers: false })) process.kill(pid, 'SIGKILL');
				stopQuietly(holder.pid, AS_A_STOP);
				rmSync(gate, { force: true });
			}
		});
	});

	describe('the detached reaper', () => {
		it('is launched by a successful start and joined, not duplicated, by the next', async () => {
			const first = new SidecarProcesses(collectingLogger());
			const state = await first.start({
				name: 'sidecar-reaper-launch-test',
				command: 'node',
				args: ['-e', LONG_RUNNING],
				fingerprint: ['v1'],
			});
			try {
				assert.strictEqual(state.started, true);
				assert.strictEqual(first.reaper?.started, true);
				assert.strictEqual(first.reaper.adopted, false, 'the first start launches the real reaper');
				assert.ok(existsSync(join(pidDir, 'harper-sidecar-reaper.pid')), 'the lock that makes it a singleton');
				if (process.platform !== 'win32') {
					// Under a keeper, as a sidecar is, and outside this node's process group, which a signal to it spares
					const held = readPidLock(join(pidDir, 'harper-sidecar-reaper.pid'));
					assert.strictEqual(held.pid, first.reaper.pid);
					assert.strictEqual(parentOf(first.reaper.pid), held.keeper, 'the reaper is not its keeper`s child');
					const group = (pid) => execFileSync('ps', ['-o', 'pgid=', '-p', String(pid)], { encoding: 'utf-8' }).trim();
					assert.notStrictEqual(group(first.reaper.pid), group(process.pid), 'the reaper shares this node`s group');
				}

				// The descriptor beside the lock is what the shutdown path and the reaper act from
				const descriptor = JSON.parse(readFileSync(join(pidDir, 'sidecar-reaper-launch-test.sidecar.json'), 'utf-8'));
				assert.strictEqual(descriptor.pid, state.pid);
				assert.strictEqual(descriptor.command, 'node');
				assert.strictEqual(descriptor.pidFile, join(pidDir, 'sidecar-reaper-launch-test.pid'));

				const second = supervised.make(collectingLogger());
				await second.start({
					name: 'sidecar-reaper-launch-test',
					command: 'node',
					args: ['-e', LONG_RUNNING],
					fingerprint: ['v1'],
				});
				assert.strictEqual(second.reaper?.adopted, true, 'a second thread must join the reaper, not start another');
				assert.strictEqual(second.reaper.pid, first.reaper.pid);
			} finally {
				stopQuietly(state.pid, AS_A_STOP);
				stopQuietly(first.reaper?.pid, AS_A_STOP);
			}
		});

		it('runs under a keeper that restarts its count after a stable run, a singleton for this lock', async function () {
			if (process.platform === 'win32') this.skip();
			const handed = [];
			const keep = (command, args, options) => {
				handed.push(options);
				return spawnKept(command, args, options);
			};
			const processes = supervised.make(collectingLogger(), { keep });
			const state = await processes.start({
				name: 'sidecar-reaper-options-test',
				command: 'node',
				args: ['-e', LONG_RUNNING],
			});
			try {
				const reaper = handed.find((options) => options.name === REAPER_NAME);
				assert.ok(reaper, 'the reaper was not started through the keeper');
				assert.strictEqual(reaper.stableMs, 60_000, 'the reaper`s cap would bound its lifetime, not a crash loop');
				assert.deepStrictEqual(reaper.identity, ['--self-pid-file', join(pidDir, `${REAPER_NAME}.pid`)]);
				assert.strictEqual(reaper.detached, true);
				assert.strictEqual(reaper.fork, true);
				const sidecar = handed.find((options) => options.name === 'sidecar-reaper-options-test');
				assert.strictEqual(sidecar.stableMs, undefined, 'a sidecar`s keeper restarts its count');
			} finally {
				stopQuietly(state.pid, AS_A_STOP);
				stopQuietly(processes.reaper?.pid, AS_A_STOP);
			}
		});

		it('is skipped when the descriptor opts out', async () => {
			const processes = supervised.make(collectingLogger());
			const state = await processes.start({
				name: 'sidecar-noreaper-test',
				command: 'node',
				args: ['-e', LONG_RUNNING],
				reaper: false,
			});
			try {
				assert.strictEqual(state.started, true);
				assert.strictEqual(processes.reaper, undefined);
				assert.strictEqual(existsSync(join(pidDir, 'harper-sidecar-reaper.pid')), false);
			} finally {
				stopQuietly(state.pid, AS_A_STOP);
			}
		});
	});

	describe('Scope wiring', () => {
		it('exposes processes as a lazy getter on Scope', () => {
			const { Scope } = require('#src/components/Scope');
			const descriptor = Object.getOwnPropertyDescriptor(Scope.prototype, 'processes');
			assert.strictEqual(typeof descriptor?.get, 'function');
		});
	});
});

// A refused restart has to clear the fields #rejoinReplacement clears when nothing replaces a dead process
describe('a restart that cannot spawn', () => {
	failOnSurvivors();
	useTestTiming();

	it('publishes the process as not running rather than as the pid that died', async () => {
		const logger = collectingLogger();
		let spawns = 0;
		const real = require('#src/security/processSupervisor/constrainedChildProcess').child_processConstrained.spawn;
		// The first start gets a real child; every restart is refused, as an allowlist or a missing binary would
		const spawn = (command, args, options) => {
			if (++spawns > 1) throw new Error('is not allowed');
			return real(command, args, options);
		};
		// No keeper, so the refused spawn is the one a restart makes; a keeper restarts without asking this thread
		const processes = new SidecarProcesses(logger, spawn, undefined, null);
		const state = await processes.start({
			name: 'sidecar-failed-restart-test',
			// Bare `node`, which the allowlist admits, so this test's refusal is the one under test
			command: 'node',
			args: ['-e', 'process.exit(3)'],
			reaper: false,
		});

		// It exits 3 immediately, which takes the restart path, and that restart is refused.
		await waitFor(() => state.error !== undefined, {
			timeout: RESPAWN_SETTLE_MS + 3000,
			message: 'the refused restart never recorded an error',
		});
		assert.strictEqual(spawns, 2, 'the restart must have been attempted');
		assert.strictEqual(state.started, false, 'a process that is not running must not read started');
		assert.strictEqual(state.pid, undefined, 'and must not publish the pid that died');
		assert.match(state.error, /is not allowed/, 'the reason stays on the state');
	});
});

// The budget bounds a crash loop, not the node's lifetime, so a long-lived node still answers a reaper's death
describe('the reaper replacement budget', () => {
	it('counts up while a replacement keeps dying fast', () => {
		assert.strictEqual(nextReaperAttempt(0, 500), 1);
		assert.strictEqual(nextReaperAttempt(1, 500), 2);
		assert.strictEqual(nextReaperAttempt(4, 500), 5, 'the last attempt inside the budget');
	});

	it('gives up once a crash loop has spent the budget', () => {
		assert.strictEqual(nextReaperAttempt(5, 500), null);
		assert.strictEqual(nextReaperAttempt(9, 0), null);
	});

	it('starts a fresh count after a replacement that stayed up', () => {
		assert.strictEqual(nextReaperAttempt(4, 60_001), 0, 'a reaper that ran is not a continuing failure');
		// A spent budget, then a reaper that ran for an hour: the next death is still answered
		assert.strictEqual(nextReaperAttempt(5, 3_600_000), 0);
	});

	it('NEGATIVE: the boundary is exclusive, so a reaper that lasted exactly the window is still a failure', () => {
		assert.strictEqual(nextReaperAttempt(2, 60_000), 3);
	});
});
