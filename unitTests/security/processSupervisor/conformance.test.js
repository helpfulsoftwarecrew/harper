'use strict';

// The keeper and the reaper run under bare node and cannot load TypeScript, so each keeps a copy of a rule the
// TypeScript side owns. Each table below runs both copies over the inputs it lists and fails where they answer one of
// those differently; a rule that no row reaches can drift in either copy without a failure here.

const assert = require('node:assert');
const { execFileSync, spawn } = require('node:child_process');
const { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, utimesSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const { waitFor } = require('../../waitFor.js');
const { TEST_TIMING } = require('./helpers.js');
const {
	LONG_RUNNING,
	MARKERS,
	failOnSurvivors,
	spawnExecdShell,
	spawnForeign,
	spawnOwnBinary,
	stopQuietly,
} = require('./reap.js');
const { makeZombie } = require('./zombieProcess.js');
const env = require('#src/utility/environment/environmentManager');
const {
	KEEPER_SCRIPT,
	identifyKeeper,
	identifyKept,
	identifyProcess,
	isProcessAlive,
	parentOf,
	platformCanIdentifyProcesses,
	startedAt,
} = require('#src/security/processSupervisor/processIdentity');
const { CLAIM_TIMEOUT_MS, readPidLock, tryPidFileLockGate } = require('#src/security/processSupervisor/pidFileLock');
const { readSidecarTargets, writeSidecarTarget } = require('#src/security/processSupervisor/sidecarRegistry');
const { lockPathFor } = require('#src/security/processSupervisor/constrainedChildProcess');
const reaper = require('#js/security/processSupervisor/sidecarReaper');
// The copy a keeper runs, from its path, rather than the one the build emits beside it
const keeper = require(KEEPER_SCRIPT);

const DEAD_PID = 2147483646;
const FIXTURE = join(__dirname, 'fixtures', 'supervisedProcess.mjs');

/** Runs `read` with this process's locale set to C alone, as a service started by launchd can have it. */
function inTheCLocale(read) {
	const isLocale = (key) => key === 'LANG' || key.startsWith('LC_');
	const saved = Object.fromEntries(Object.entries(process.env).filter(([key]) => isLocale(key)));
	for (const key of Object.keys(saved)) delete process.env[key];
	process.env.LC_ALL = 'C';
	try {
		return read();
	} finally {
		delete process.env.LC_ALL;
		Object.assign(process.env, saved);
	}
}

/** readPidLock's answer without the one field only the TypeScript side reads, the claimant's start. */
function withoutClaimantStart(lock) {
	if (lock === null) return null;
	const { claimantStarted: _unused, ...rest } = lock;
	return rest;
}

describe('the copies that stay copies', function () {
	failOnSurvivors();
	this.timeout(20000);
	let dir;

	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), 'supervisor-conformance-'));
	});

	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
	});

	describe("the lock's parse: sidecarKeeper.js readLock against pidFileLock.ts readPidLock", () => {
		const record = JSON.stringify({ token: 't1', host: 11, keeper: 22, keeperArgv: ['node', 'k.js'], started: 's' });
		const contents = {
			commit: '123\n7\n',
			pidOnly: '123',
			keeperCommit: `123\n7\n${record}\n`,
			keeperCommitNoTrailingNewline: `123\n7\n${record}`,
			recordWithNonStringArgv: `123\n7\n${JSON.stringify({ token: 't', keeper: 22, keeperArgv: ['node', 5] })}\n`,
			recordWithKeeperZero: `123\n7\n${JSON.stringify({ token: 't', keeper: 0, keeperArgv: ['node'] })}\n`,
			tornRecord: '123\n7\n{"token":',
			claim: '\n0\n456\ntok\nstart-of-456',
			claimNoStart: '\n0\n456\ntok\n',
			claimNoToken: '\n0\n456',
			empty: '',
			blank: '  \n',
			newlineOnly: '\n',
			newlinesOnly: '\n\n',
			junk: 'abc',
			badVersion: '123\nabc\n',
			negativePid: '-5\n1\n',
			leadingSpace: ' 4567\n9',
			crlf: '4567\r\n9\r\n',
		};

		for (const [name, content] of Object.entries(contents)) {
			it(`reads ${name} alike`, () => {
				const path = join(dir, `${name}.pid`);
				writeFileSync(path, content);
				assert.deepStrictEqual(keeper.readLock(path), withoutClaimantStart(readPidLock(path)));
			});
		}

		it('reads an absent lock alike', () => {
			assert.strictEqual(keeper.readLock(join(dir, 'absent.pid')), null);
			assert.strictEqual(readPidLock(join(dir, 'absent.pid')), null);
		});

		it('reads a claim`s version as 0, not as the claimant on its second line', () => {
			const path = join(dir, 'claim.pid');
			writeFileSync(path, '\n0\n456\ntok\n');
			assert.strictEqual(readPidLock(path).version, 0);
			assert.strictEqual(readPidLock(path).claimant, 456);
		});

		// The readers this parse replaced read line one alone; kept here verbatim as the oracle
		function readLockedPid(path) {
			try {
				const pid = Number.parseInt(readFileSync(path, 'utf-8').trim().split('\n')[0] ?? '', 10);
				return Number.isInteger(pid) ? pid : null;
			} catch {
				return null;
			}
		}

		it('names the same pid as the line-one reader it replaced, wherever a caller asks for the pid alone', () => {
			for (const [name, content] of Object.entries(contents)) {
				const path = join(dir, `${name}.pid`);
				writeFileSync(path, content);
				const expected = readLockedPid(path);
				assert.strictEqual(readPidLock(path)?.pid ?? null, expected, `${name}: pidFileLock.ts`);
				assert.strictEqual(keeper.readLock(path)?.pid ?? null, expected, `${name}: the keeper`);
			}
			assert.strictEqual(readPidLock(join(dir, 'absent.pid'))?.pid ?? null, readLockedPid(join(dir, 'absent.pid')));
		});

		// keeperOwesRestart's old body, which parsed line three for itself; kept here verbatim as the oracle
		function keeperOwedByLineThree(path) {
			try {
				const parsed = JSON.parse(readFileSync(path, 'utf-8').split('\n')[2] ?? '');
				if (!Number.isInteger(parsed?.keeper) || !Array.isArray(parsed?.keeperArgv)) return false;
				return identifyKeeper(parsed.keeper, parsed.keeperArgv) !== 'differs';
			} catch {
				return false;
			}
		}

		it('says a keeper is owed its restart exactly where line three`s own parse said so', async function () {
			if (!platformCanIdentifyProcesses()) this.skip();
			const standIn = spawnOwnBinary();
			try {
				await waitFor(() => isProcessAlive(standIn.pid));
				const argv = [process.execPath, '-e', LONG_RUNNING];
				const rows = {
					liveKeeper: `${DEAD_PID}\n7\n${JSON.stringify({ token: 't', keeper: standIn.pid, keeperArgv: argv })}\n`,
					keeperOne: `${DEAD_PID}\n7\n${JSON.stringify({ token: 't', keeper: 1, keeperArgv: ['/sbin/init'] })}\n`,
					goneKeeper: `${DEAD_PID}\n7\n${JSON.stringify({ token: 't', keeper: DEAD_PID - 1, keeperArgv: argv })}\n`,
					claim: '\n0\n456\ntok\n',
					barePid: `${DEAD_PID}\n7`,
				};
				for (const [name, content] of Object.entries(rows)) {
					const path = join(dir, `${name}.pid`);
					writeFileSync(path, content);
					const lock = readPidLock(path);
					const owed =
						lock?.keeper !== undefined &&
						lock.keeperArgv !== undefined &&
						identifyKeeper(lock.keeper, lock.keeperArgv) !== 'differs';
					assert.strictEqual(owed, keeperOwedByLineThree(path), name);
				}
			} finally {
				stopQuietly(standIn.pid);
			}
		});
	});

	describe("the gate: sidecarKeeper.js takeGate against pidFileLock.ts's", () => {
		/** What a take leaves: whether it was taken, and the pid and start lines of each file still standing. */
		function leftBehind(path) {
			const lines = (file) => {
				try {
					return readFileSync(file, 'utf-8').split('\n').slice(0, 2).join('\n');
				} catch (error) {
					return error.code;
				}
			};
			return { gate: lines(`${path}.claiming`), breaker: lines(`${path}.claiming.breaking`) };
		}

		function takeByLock(path) {
			return tryPidFileLockGate(path, () => true, 0) === true;
		}

		// The keeper's own abandon age, which every keeper and reaper call takes by default, not one handed to it
		function takeByKeeper(path) {
			const nonce = keeper.takeGate(path, keeper.GATE_WAIT_MS);
			if (nonce === null) return false;
			keeper.releaseHeld(`${path}.claiming`, nonce);
			return true;
		}

		const rows = [
			['no gate', () => ({})],
			['a gate a dead holder left', () => ({ gate: `${DEAD_PID}\n\nleft` })],
			['a gate left under a reissued pid', ({ reissued }) => ({ gate: `${reissued}\nThu Jan  1 00:00:00 1970\nleft` })],
			['a live holder`s young gate', ({ own }) => ({ gate: `${process.pid}\n${own}\nheld` })],
			[
				'a live holder`s gate held past 30 s',
				({ own }) => ({ gate: `${process.pid}\n${own}\nheld`, gateAgeMs: 31_000 }),
			],
			['a live holder`s gate held 29 s', ({ own }) => ({ gate: `${process.pid}\n${own}\nheld`, gateAgeMs: 29_000 })],
			['a gate that cannot be read', () => ({ gateIsDirectory: true })],
			['a dead breaker beside a dead gate', () => ({ gate: `${DEAD_PID}\n\nleft`, breaker: `${DEAD_PID}\n\nleft` })],
			[
				'a live breaker`s young file beside a dead gate',
				({ own }) => ({ gate: `${DEAD_PID}\n\nleft`, breaker: `${process.pid}\n${own}\nbreaking` }),
			],
		];

		for (const [label, arrange] of rows) {
			it(`answers ${label} alike, and leaves the same files`, async function () {
				if (!platformCanIdentifyProcesses()) this.skip();
				const stranger = spawnForeign();
				try {
					await waitFor(() => isProcessAlive(stranger.pid));
					const files = arrange({ reissued: stranger.pid, own: startedAt(process.pid) ?? '' });
					const answers = [takeByLock, takeByKeeper].map((take) => {
						const path = join(dir, `${take.name}.pid`);
						if (files.gate) writeFileSync(`${path}.claiming`, files.gate);
						if (files.gateIsDirectory) mkdirSync(`${path}.claiming`);
						if (files.breaker) writeFileSync(`${path}.claiming.breaking`, files.breaker);
						if (files.gateAgeMs) {
							const at = (Date.now() - files.gateAgeMs) / 1000;
							utimesSync(`${path}.claiming`, at, at);
						}
						return { taken: take(path), ...leftBehind(path) };
					});
					assert.deepStrictEqual(answers[1], answers[0], 'the keeper answered otherwise than the lock');
				} finally {
					stopQuietly(stranger.pid);
				}
			});
		}

		it('abandons a live holder`s gate at the age the lock does', () => {
			assert.strictEqual(keeper.GATE_WAIT_MS, CLAIM_TIMEOUT_MS);
		});

		// What each copy's linkGate writes, read while it holds the gate
		function linkedByLock(path) {
			return tryPidFileLockGate(path, () => readFileSync(`${path}.claiming`, 'utf-8'), 0);
		}

		function linkedByKeeper(path) {
			const nonce = keeper.takeGate(path, keeper.GATE_WAIT_MS);
			try {
				return readFileSync(`${path}.claiming`, 'utf-8');
			} finally {
				keeper.releaseHeld(`${path}.claiming`, nonce);
			}
		}

		it('writes the same pid and start lines from either copy, and each breaks at once what the other left under a reissued pid', async function () {
			if (!platformCanIdentifyProcesses()) this.skip();
			const stranger = spawnForeign();
			try {
				await waitFor(() => isProcessAlive(stranger.pid) && startedAt(stranger.pid) !== null);
				const linked = [linkedByLock, linkedByKeeper].map((link) => link(join(dir, `${link.name}.pid`)));
				const startLine = linked[0].split('\n')[1];
				assert.deepStrictEqual(
					linked.map((content) => content.split('\n').slice(0, 2)),
					[
						[String(process.pid), startedAt(process.pid)],
						[String(process.pid), startedAt(process.pid)],
					]
				);
				// Each copy's gate as a holder killed inside it leaves it, its pid since reissued to another process
				for (const [linker, judge] of [
					[linkedByKeeper, takeByLock],
					[linkedByLock, takeByKeeper],
				]) {
					const path = join(dir, `${linker.name}-${judge.name}.pid`);
					const [, start, nonce] = linker(join(dir, `${linker.name}-source.pid`)).split('\n');
					assert.strictEqual(start, startLine);
					writeFileSync(`${path}.claiming`, `${stranger.pid}\n${start}\n${nonce}`);
					assert.strictEqual(
						judge(path),
						true,
						`${judge.name} waited on a gate ${linker.name} left under a reissued pid`
					);
				}
			} finally {
				stopQuietly(stranger.pid);
			}
		});
	});

	describe('the start-time read: sidecarKeeper.js inspect against what processIdentity.ts reads through it', () => {
		// A keeper outlives the node across a restart and an upgrade, so the format both sides compare is pinned here
		it('reads a start time as `ps` prints it in the C locale and UTC, whatever the caller`s locale and zone', function () {
			if (process.platform !== 'darwin') this.skip();
			const saved = { LANG: process.env.LANG, LC_ALL: process.env.LC_ALL, TZ: process.env.TZ };
			Object.assign(process.env, { LANG: 'de_DE.UTF-8', LC_ALL: 'de_DE.UTF-8', TZ: 'America/New_York' });
			try {
				const printed = execFileSync('ps', ['-p', String(process.pid), '-o', 'lstart='], {
					encoding: 'utf-8',
					env: { PATH: process.env.PATH, LC_ALL: 'C', TZ: 'UTC' },
				});
				assert.strictEqual(startedAt(process.pid), printed.trim().split(/\s+/).join(' '));
				assert.strictEqual(keeper.startedAt(process.pid), startedAt(process.pid));
			} finally {
				for (const [key, value] of Object.entries(saved)) {
					if (value === undefined) delete process.env[key];
					else process.env[key] = value;
				}
			}
		});

		it('reads liveness, parent and start alike for every kind of pid', async function () {
			if (!platformCanIdentifyProcesses()) this.skip();
			const own = spawnOwnBinary();
			const shell = spawnExecdShell();
			const foreign = spawnForeign();
			const zombie = await makeZombie();
			try {
				await waitFor(() => [own, shell, foreign].every((child) => isProcessAlive(child.pid)));
				await waitFor(() => identifyProcess(shell.pid, '/bin/sh') === 'differs', { message: 'sh never exec`d' });
				const pids = [process.pid, own.pid, shell.pid, foreign.pid, zombie.zombiePid, DEAD_PID, 0, -1];
				for (const pid of pids) {
					const thread = { alive: isProcessAlive(pid), ppid: parentOf(pid), started: startedAt(pid) };
					assert.deepStrictEqual(keeper.inspect(pid), thread, `pid ${pid}`);
				}
			} finally {
				zombie.release();
				for (const child of [own, shell, foreign]) stopQuietly(child.pid);
			}
		});
	});

	describe("identification: sidecarReaper.js's copy against processIdentity.ts", () => {
		it('answers every case alike', async function () {
			if (!platformCanIdentifyProcesses()) this.skip();
			const own = spawnOwnBinary();
			const shell = spawnExecdShell();
			const foreign = spawnForeign();
			const scripted = spawn(process.execPath, [FIXTURE], { stdio: 'ignore' });
			const keeperLike = spawn(process.execPath, ['-e', LONG_RUNNING, '/x/sidecarKeeper.js', '--keep', 'y'], {
				stdio: 'ignore',
			});
			// Another binary carrying the right script among its arguments
			const tailing = spawn('/usr/bin/tail', ['-f', FIXTURE], { stdio: 'ignore' });
			const children = [own, shell, foreign, scripted, keeperLike, tailing];
			// A file by the fixture's name somewhere else, which agrees by name only and so cannot tell
			const sameName = join(dir, 'supervisedProcess.mjs');
			writeFileSync(sameName, '');
			try {
				await waitFor(() => children.every((child) => isProcessAlive(child.pid)));
				await waitFor(() => identifyProcess(shell.pid, '/bin/sh') === 'differs', { message: 'sh never exec`d' });
				const cases = [
					['node as this node binary', own.pid, process.execPath],
					['node as /bin/sleep', own.pid, '/bin/sleep'],
					['an exec`d sh as /bin/sh', shell.pid, '/bin/sh'],
					['an exec`d sh by its recorded start', shell.pid, '/bin/sh', undefined, { started: startedAt(shell.pid) }],
					[
						'an exec`d sh under another start',
						shell.pid,
						'/bin/sh',
						undefined,
						{ started: 'Thu Jan  1 00:00:00 1970' },
					],
					['sleep by a bare name', foreign.pid, 'sleep'],
					// darwin reports a process found on PATH by its bare name, which agrees with the path by name alone
					['sleep found on PATH, asked as /bin/sleep', foreign.pid, '/bin/sleep'],
					['another binary running the right script', tailing.pid, process.execPath, FIXTURE],
					['a node script, the right one', scripted.pid, process.execPath, FIXTURE],
					['a node script, another one', scripted.pid, process.execPath, join(__dirname, 'reap.js')],
					['a node script by its name at another path', scripted.pid, process.execPath, sameName],
					['a keeper`s command line as node', keeperLike.pid, process.execPath],
					['a dead pid', DEAD_PID, process.execPath],
					['pid 0', 0, process.execPath],
					[
						'a child vouched for by the keeper that is its parent',
						own.pid,
						'/bin/sleep',
						undefined,
						{ keeper: process.pid, keeperArgv: process.argv.slice(0, 1) },
					],
				];
				for (const [label, pid, command, script, kept] of cases) {
					const thread = kept ? identifyKept(pid, command, script, kept) : identifyProcess(pid, command, script);
					const copy = kept ? reaper.identifyKept(pid, command, script, kept) : reaper.identify(pid, command, script);
					assert.strictEqual(copy, thread, label);
				}
			} finally {
				for (const child of children) stopQuietly(child.pid);
			}
		});

		it('reads a keeper`s command line alike, a path outside ASCII included', async function () {
			if (!platformCanIdentifyProcesses()) this.skip();
			const paths = ['/tmp/harper-root/pids/x.pid', '/tmp/harper-café/pids/x.pid'];
			const standIns = paths.map((path) => spawn(process.execPath, ['-e', LONG_RUNNING, path], { stdio: 'ignore' }));
			try {
				await waitFor(() => standIns.every((child) => isProcessAlive(child.pid)));
				for (const [index, child] of standIns.entries()) {
					const argv = [process.execPath, '-e', LONG_RUNNING, paths[index]];
					assert.strictEqual(reaper.argvLeads(child.pid, argv), identifyKeeper(child.pid, argv), paths[index]);
					assert.strictEqual(identifyKeeper(child.pid, argv), 'match', `${paths[index]}: the stand-in is not running`);
				}
			} finally {
				for (const child of standIns) stopQuietly(child.pid);
			}
		});

		it('answers alike, and positively, for a process under a path outside ASCII in the C locale', async function () {
			if (!platformCanIdentifyProcesses()) this.skip();
			mkdirSync(join(dir, 'café'));
			const node = join(dir, 'café', 'node');
			symlinkSync(process.execPath, node);
			const argv = [node, '-e', LONG_RUNNING, join(dir, 'café', 'x.pid')];
			const child = spawn(argv[0], argv.slice(1), { stdio: 'ignore' });
			try {
				await waitFor(() => isProcessAlive(child.pid));
				const [thread, copy] = inTheCLocale(() => [
					[identifyProcess(child.pid, node), identifyKeeper(child.pid, argv)],
					[reaper.identify(child.pid, node), reaper.argvLeads(child.pid, argv)],
				]);
				assert.deepStrictEqual(copy, thread, 'the reaper answered otherwise than processIdentity.ts');
				assert.deepStrictEqual(thread, ['match', 'match']);
			} finally {
				stopQuietly(child.pid);
			}
		});
	});

	describe('the descriptor: sidecarReaper.js readTargets against sidecarRegistry.ts, which writes it', () => {
		it('reads what the registry writes, and refuses what it refuses', () => {
			writeSidecarTarget(dir, { name: 'plain', pidFile: join(dir, 'plain.pid'), pid: 101, command: '/opt/plain' });
			writeSidecarTarget(dir, {
				name: 'scripted',
				pidFile: join(dir, 'scripted.pid'),
				pid: 102,
				command: process.execPath,
				script: '/opt/agent.js',
				started: 'Thu Jan  1 00:00:00 1970',
			});
			const hand = (name, body) => writeFileSync(join(dir, `${name}.sidecar.json`), body);
			hand('nocommand', JSON.stringify({ name: 'nocommand', pidFile: join(dir, 'nocommand.pid'), pid: 103 }));
			hand('numcommand', JSON.stringify({ name: 'numcommand', pidFile: join(dir, 'x.pid'), pid: 104, command: 7 }));
			hand(
				'fractionalpid',
				JSON.stringify({ name: 'fractionalpid', pidFile: join(dir, 'y.pid'), pid: 1.5, command: 'x' })
			);
			hand(
				'emptystart',
				JSON.stringify({ name: 'emptystart', pidFile: join(dir, 'z.pid'), pid: 105, command: 'z', started: '' })
			);
			hand('torn', '{"name":');
			writeFileSync(join(dir, 'notadescriptor.json'), '{}');
			const byName = (a, b) => a.name.localeCompare(b.name);
			assert.deepStrictEqual(reaper.readTargets({ pidDir: dir }).sort(byName), readSidecarTargets(dir).sort(byName));
			assert.deepStrictEqual(
				readSidecarTargets(dir)
					.map((target) => target.name)
					.sort(),
				['emptystart', 'plain', 'scripted']
			);
		});
	});

	describe("the death record: sidecarLifecycle.ts reads the keeper's own reader", () => {
		// The lifecycle's reader before it took the keeper's, kept here verbatim as the oracle
		const OUTCOMES = new Set(['released', 'restarting', 'gave-up', 'gone', 'taken', 'failed']);
		function readKeeperRecord(lockPath) {
			try {
				const record = JSON.parse(readFileSync(`${lockPath}.exit`, 'utf-8'));
				if (typeof record?.token !== 'string' || !OUTCOMES.has(record.outcome) || !Number.isInteger(record.pid))
					return null;
				return record;
			} catch {
				return null;
			}
		}

		it('accepts and refuses the records the lifecycle`s own reader did', () => {
			const valid = { token: 't', keeper: 5, pid: 6, code: 1, signal: null, outcome: 'restarting', restarts: 1 };
			const rows = {
				valid: JSON.stringify(valid),
				unknownOutcome: JSON.stringify({ ...valid, outcome: 'stopped' }),
				fractionalPid: JSON.stringify({ ...valid, pid: 6.5 }),
				noToken: JSON.stringify({ ...valid, token: undefined }),
				torn: '{"token":',
			};
			for (const [name, body] of Object.entries(rows)) {
				const lock = join(dir, `${name}.pid`);
				writeFileSync(`${lock}.exit`, body);
				assert.deepStrictEqual(keeper.readRecord(lock), readKeeperRecord(lock), name);
			}
			assert.strictEqual(keeper.readRecord(join(dir, 'absent.pid')), readKeeperRecord(join(dir, 'absent.pid')));
		});
	});

	describe('a deliberate stop: the keeper`s rule, which the lifecycle now grades by', () => {
		it('grades every exit as the lifecycle`s own expressions did', () => {
			// The owner's and the forked reaper's expressions before they took the keeper's, kept here verbatim
			const owner = (code, signal) =>
				signal ? signal === 'SIGTERM' || signal === 'SIGINT' || signal === 'SIGHUP' : code === 0;
			const forkedReaper = (code, signal) =>
				code === 0 || signal === 'SIGTERM' || signal === 'SIGINT' || signal === 'SIGHUP';
			const exits = [
				[0, null],
				[1, null],
				[143, null],
				[null, 'SIGTERM'],
				[null, 'SIGINT'],
				[null, 'SIGHUP'],
				[null, 'SIGKILL'],
				[null, 'SIGSEGV'],
				[null, 'SIGQUIT'],
				[null, 'SIGUSR2'],
			];
			for (const [code, signal] of exits) {
				assert.strictEqual(keeper.isDeliberate(code, signal), owner(code, signal), `${code} ${signal}`);
				assert.strictEqual(keeper.isDeliberate(code, signal), forkedReaper(code, signal), `${code} ${signal}`);
			}
		});
	});

	describe("the suite's own helpers", () => {
		it('names a sidecar`s lock where the spawn claims it', () => {
			assert.strictEqual(lockPathFor('x'), join(env.getHdbBasePath(), 'pids', 'x.pid'));
		});

		it('scales the shipped timing down to the values every suite sets', () => {
			assert.deepStrictEqual({ ...TEST_TIMING }, { respawnBaseMs: 50, rejoinPollMs: 10, rejoinGraceMs: 750 });
		});

		it('sweeps for the script its node fixtures run', () => {
			assert.ok(MARKERS.includes(LONG_RUNNING));
		});

		it('stops a positive pid only, with SIGKILL unless told otherwise', () => {
			const sent = [];
			const kill = process.kill;
			process.kill = (pid, signal) => sent.push([pid, signal]);
			try {
				stopQuietly(1234);
				stopQuietly(1234, { signal: 'SIGTERM' });
				for (const pid of [0, -1, undefined, Number.NaN, 1.5]) stopQuietly(pid);
				// forEach hands the index as the second argument, which must not read as a signal
				[4321, 4322].forEach(stopQuietly);
			} finally {
				process.kill = kill;
			}
			assert.deepStrictEqual(sent, [
				[1234, 'SIGKILL'],
				[1234, 'SIGTERM'],
				[4321, 'SIGKILL'],
				[4322, 'SIGKILL'],
			]);
		});
	});
});
