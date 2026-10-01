'use strict';

const hdbTerms = require('../hdbTerms.ts');
const servicesConfig = require('./servicesConfig.js');
const envMangr = require('../environment/environmentManager.ts');
const hdbLogger = require('../../utility/logging/harper_logger.ts');
const { onMessageFromWorkers } = require('../../server/threads/manageThreads.js');
const fs = require('fs');
const path = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');
const { execFile, fork } = require('node:child_process');
const { executableOf, isProcessAlive } = require('./processIdentity.js');

const INIT_PROCESS_NAMES = new Set(['catatonit', 'docker-init', 'dumb-init', 'init', 's6-svscan', 'systemd', 'tini']);
// Every runtime a Harper main process can be: a live holder is stale only once identified as none of these
const RUNTIME_PROCESS_NAMES = new Set(['bun', 'harper', 'node', 'nodejs']);
const NOT_RUNNING = 'is not running';

module.exports = {
	start,
	restart,
	kill,
	startService,
	getHdbPid,
	staleHdbPidReason,
	isProcessRunning,
	cleanupChildrenProcesses,
	expectedRestartOfChildren,
};

onMessageFromWorkers((message) => {
	if (message.type === 'restart') envMangr.initSync(true);
});

let childProcesses = [];
const MAX_RESTARTS = 10;
let shuttingDown;
/**
 * Starts a service
 * @param procConfig
 * @returns void
 */
function start(procConfig, noKill = false) {
	const args = typeof procConfig.args === 'string' ? procConfig.args.split(' ') : procConfig.args;
	procConfig.silent = true;
	procConfig.detached = true;
	procConfig.env = {
		...procConfig.env,
		HARPER_PARENT_PROCESS_PID: process.pid.toString(),
	};
	const subprocess = procConfig.script
		? fork(procConfig.script, args, procConfig)
		: execFile(procConfig.binFile, args, procConfig);
	subprocess.name = procConfig.name;
	subprocess.config = procConfig;
	subprocess.on('error', (code, message) => {
		console.error(code, message);
	});
	subprocess.on('exit', async (code) => {
		let index = childProcesses.indexOf(subprocess); // dead, remove it from processes to kill now
		if (index > -1) childProcesses.splice(index, 1);
		if (!shuttingDown && code !== 0) {
			procConfig.restarts = (procConfig.restarts || 0) + 1;
			// restart the child process
			if (procConfig.restarts < MAX_RESTARTS) {
				start(procConfig);
			}
		}
	});

	subprocess.stdout.on('data', (log) => hdbLogger.info(log.toString()));
	subprocess.stderr.on('data', (log) => hdbLogger.error(log.toString()));
	subprocess.unref();

	// if we are running in standard mode, then we want to clean up our child processes when we exit
	if (childProcesses.length === 0) {
		if (!noKill) {
			process.on('exit', cleanupChildrenProcesses);
			process.on('SIGINT', cleanupChildrenProcesses);
			process.on('SIGQUIT', cleanupChildrenProcesses);
			process.on('SIGTERM', cleanupChildrenProcesses);
		}
	}
	childProcesses.push(subprocess);
}
function cleanupChildrenProcesses(exit = true) {
	if (shuttingDown) return;
	shuttingDown = true;
	if (childProcesses.length === 0) return;
	hdbLogger.info('Killing child processes...');
	childProcesses.map((proc) => proc.kill());
	if (exit) process.exit(0);
	else return delay(2000); // give these processes some time to exit
}

/**
 * restart processes
 * @param serviceName
 * @returns {Promise<unknown>}
 */
function restart(serviceName) {
	expectedRestartOfChildren();
	for (let childProcess of childProcesses) {
		// kill the child process and let it (auto) restart
		if (childProcess.name === serviceName) {
			childProcess.kill();
		}
	}
}

/**
 * Reset the restart counts for all child processes because we are doing an intentional restart
 */
function expectedRestartOfChildren() {
	for (let childProcess of childProcesses) {
		if (childProcess.config) childProcess.config.restarts = 0; // reset the restart count
	}
}

/**
 * Checks to see if Harper is currently running, returning the pid if it is
 * @returns {number|undefined}
 */
function getHdbPid() {
	const harperPath = envMangr.getHdbBasePath();
	if (!harperPath) return;
	const pidFile = path.join(harperPath, hdbTerms.HDB_PID_FILE);
	const hdbPid = readPidFile(pidFile);
	if (!hdbPid || hdbPid === process.pid) return;
	const staleReason = staleHdbPidReason(hdbPid);
	// A live runtime process, or one this platform cannot identify: refusing keeps two nodes from racing
	if (staleReason === null) return hdbPid;
	if (staleReason !== NOT_RUNNING) hdbLogger.warn(`Ignoring stale pid file ${pidFile}: pid ${hdbPid} ${staleReason}`);
}

/** Why a pid read from hdb.pid is not a Harper still up, or null when it may be one. A live holder this platform
 * cannot identify gets null, so run, stop and status all treat it as Harper. */
function staleHdbPidReason(pid) {
	// A persistent volume from an older image may contain PID 1 after the current image puts an init at that PID.
	if (pid === 1 && isInitProcess(pid)) return 'is the init process, not Harper';
	// Zombie-aware on Linux and darwin, unlike bare kill(pid, 0): a dead-but-unreaped holder is not an earlier Harper still up
	if (!isProcessAlive(pid)) return NOT_RUNNING;
	const executable = executableOf(pid);
	if (executable !== null && !isRuntimeExecutable(executable)) return `is running ${executable}, not Harper`;
	return null;
}

// A holder running any known runtime, or a path resolving to this process's own binary, may be a Harper
function isRuntimeExecutable(executable) {
	if (RUNTIME_PROCESS_NAMES.has(path.basename(executable).toLowerCase())) return true;
	try {
		return fs.realpathSync(executable) === fs.realpathSync(process.execPath);
	} catch {
		// Unresolvable, as a bare name from darwin's ps usually is: not shown to be this process's binary
		return false;
	}
}

function isInitProcess(pid) {
	try {
		const executable = path.basename(fs.readlinkSync(`/proc/${pid}/exe`)).replace(/ \(deleted\)$/, '');
		if (INIT_PROCESS_NAMES.has(executable)) return true;
	} catch {
		// Some procfs configurations expose the process name but restrict the executable symlink.
	}
	try {
		return INIT_PROCESS_NAMES.has(fs.readFileSync(`/proc/${pid}/comm`, 'utf8').trim());
	} catch {
		// Fail closed: an unidentified live PID still blocks a second Harper process.
		return false;
	}
}
function kill() {
	for (let process of childProcesses) {
		process.kill();
	}
	childProcesses = [];
	return;
}

/**
 * start a specific service
 * @param serviceName
 * @returns {Promise<void>}
 */
async function startService(serviceName, noKill = false) {
	let startConfig;
	serviceName = serviceName.toLowerCase();
	switch (serviceName) {
		case hdbTerms.PROCESS_DESCRIPTORS.HDB.toLowerCase():
			startConfig = servicesConfig.generateMainServerConfig();
			break;
		default:
			throw new Error(`Start service called with unknown service config: ${serviceName}`);
	}
	start(startConfig, noKill);
}

/**
 * Reads the Harper PID file and returns the PID as a number.
 * @param {string} pidFile - The path to the Harper PID file
 * @returns {number|null} - The PID as a number, or null if the file is not found or cannot be read
 */
function readPidFile(pidFile) {
	try {
		return Number.parseInt(fs.readFileSync(pidFile, 'utf8'), 10);
	} catch {
		return null;
	}
}

/**
 * Checks if a process is running by attempting to send a signal 0 to the process.
 * @param {number} pid - The process ID to check
 * @returns {boolean} - True if the process is running, false otherwise
 */
function isProcessRunning(pid) {
	try {
		// process.kill with signal 0 tests if process exists
		// throws error if process doesn't exist
		process.kill(pid, 0);
		return true;
	} catch (err) {
		// EPERM means process exists but we don't have permission
		// which still indicates the process is running
		if (err.code === 'EPERM') {
			return true;
		}
		return false;
	}
}
