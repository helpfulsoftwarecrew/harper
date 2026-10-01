'use strict';

const assert = require('assert');
const sinon = require('sinon');
const fs = require('fs-extra');
const { spawn } = require('node:child_process');
const os = require('node:os');
const path = require('node:path');
const env_mgr = require('#src/utility/environment/environmentManager');
const sys_info = require('#src/utility/environment/systemInformation');
const hdb_terms = require('#src/utility/hdbTerms');
const installation = require('#src/utility/installation');
const { isProcessRunning } = require('#js/utility/processManagement/processManagement');
const status_module = require('#src/bin/status');
const status = status_module.default;
const { processUptimeMs } = status_module;
const { waitFor } = require('../waitFor.js');
const { makeZombie } = require('../zombieProcess.js');

describe('processUptimeMs', () => {
	it('derives uptime in ms between two epoch timestamps', () => {
		assert.strictEqual(processUptimeMs(1_000_000, 1_000_000 + 97_702_000), 97_702_000);
	});

	it('rounds to the nearest ms', () => {
		assert.strictEqual(processUptimeMs(0, 1500.6), 1501);
	});

	it('clamps a future start time to 0', () => {
		assert.strictEqual(processUptimeMs(5000, 0), 0);
	});
});

describe('Test status module', () => {
	const sandbox = sinon.createSandbox();
	const STARTED_MS = 1_700_000_000_000; // pid-file mtime (epoch ms)
	// status identifies the pid's holder, and this test's own node reads as a runtime that may be Harper
	const HDB_PID = process.pid;
	let console_log_stub;
	let get_hdb_process_info_stub;
	let fs_stat_stub;

	const fake_hdb_process_info = {
		core: [{ pid: HDB_PID }, { pid: 55297 }],
	};

	before(() => {
		console_log_stub = sandbox.stub(console, 'log');
		env_mgr.setProperty(hdb_terms.CONFIG_PARAMS.ROOTPATH, 'unit-test');
		sandbox.stub(fs, 'readFile').resolves(String(HDB_PID));
		fs_stat_stub = sandbox.stub(fs, 'stat').resolves({ mtimeMs: STARTED_MS });
		get_hdb_process_info_stub = sandbox.stub(sys_info, 'getHDBProcessInfo').resolves(fake_hdb_process_info);
		sandbox.stub(installation, 'isHdbInstalled').returns(true);
	});

	after(() => {
		sandbox.restore();
	});

	afterEach(() => {
		sandbox.resetHistory();
		get_hdb_process_info_stub.resolves(fake_hdb_process_info);
		fs_stat_stub.resolves({ mtimeMs: STARTED_MS });
	});

	it('reports running, pid, and a formatted uptime', async () => {
		await status();
		const output = console_log_stub.args[0][0];
		assert.match(output, /status: running/);
		assert.match(output, new RegExp(`pid: ${HDB_PID}`));
		// Uptime is present and non-empty; the exact derivation is covered by the processUptimeMs tests.
		assert.match(output, /uptime: \S/);
	});

	it('omits uptime when the pid file cannot be stat-ed but still reports running + pid', async () => {
		fs_stat_stub.rejects(new Error('stat failed'));

		await status();
		assert.strictEqual(console_log_stub.args[0][0], `harperdb:\n  status: running\n  pid: ${HDB_PID}\n`);
	});

	it('reports stopped when nothing is running', async () => {
		get_hdb_process_info_stub.resolves({ core: [] });

		await status();
		assert.strictEqual(console_log_stub.args[0][0], 'harperdb:\n  status: stopped\n');
	});
});

describe('status identifies the process hdb.pid names', function () {
	let originalRoot;
	let root;

	before(function () {
		if (process.platform !== 'linux' && process.platform !== 'darwin') this.skip();
		originalRoot = env_mgr.get(hdb_terms.CONFIG_PARAMS.ROOTPATH);
		root = fs.mkdtempSync(path.join(os.tmpdir(), 'harper-status-test-'));
	});

	after(() => {
		if (root === undefined) return;
		env_mgr.setProperty(hdb_terms.CONFIG_PARAMS.ROOTPATH, originalRoot);
		fs.rmSync(root, { force: true, recursive: true });
	});

	async function statusWithPidFile(pid) {
		env_mgr.setProperty(hdb_terms.CONFIG_PARAMS.ROOTPATH, root);
		fs.writeFileSync(path.join(root, hdb_terms.HDB_PID_FILE), `${pid}\n`);
		// systeminformation reuses its process list for 500 ms on Linux, so wait until it lists the holder
		await waitFor(async () => (await sys_info.getHDBProcessInfo()).core.some((p) => p.pid === pid), {
			message: `the process list never showed pid ${pid}`,
		});
		const log = console.log;
		const printed = [];
		console.log = (...args) => printed.push(args.join(' '));
		try {
			await status();
		} finally {
			console.log = log;
		}
		return printed.join('\n');
	}

	it('NEGATIVE: reports a live process that hdb.pid names but is not Harper as stopped, not running', async () => {
		const stranger = spawn('sleep', ['600'], { stdio: 'ignore' });
		try {
			await waitFor(() => isProcessRunning(stranger.pid));
			assert.strictEqual(await statusWithPidFile(stranger.pid), 'harperdb:\n  status: stopped\n');
		} finally {
			stranger.kill('SIGKILL');
		}
	});

	it('NEGATIVE: reports a dead-but-unreaped zombie that hdb.pid names as stopped', async () => {
		const { zombiePid, release } = await makeZombie();
		try {
			assert.strictEqual(await statusWithPidFile(zombiePid), 'harperdb:\n  status: stopped\n');
		} finally {
			release();
		}
	});

	it('still reports running, with the pid, when a live process of this runtime holds it', async () => {
		const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1 << 30)'], { stdio: 'ignore' });
		try {
			await waitFor(() => isProcessRunning(child.pid));
			const printed = await statusWithPidFile(child.pid);
			assert.match(printed, /status: running/);
			assert.match(printed, new RegExp(`pid: ${child.pid}\\n`));
		} finally {
			child.kill('SIGKILL');
		}
	});
});
