'use strict';

import hdbLogger from '../utility/logging/harper_logger.ts';
import * as util from 'util';
import * as childProcess from 'child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
const exec = util.promisify(childProcess.exec);
import * as systemInformation from '../utility/environment/systemInformation.ts';
import * as envMgr from '../utility/environment/environmentManager.ts';
import * as hdbTerms from '../utility/hdbTerms.ts';
import { staleHdbPidReason } from '../utility/processManagement/processManagement.js';

const STOP_MSG = 'Stopping Harper.';

export default stop;

async function stop() {
	console.log(STOP_MSG);
	hdbLogger.notify(STOP_MSG);

	// Read before the await, as getHDBProcessInfo reads it, so both name the same pid file
	const rootPath = envMgr.get(hdbTerms.CONFIG_PARAMS.ROOTPATH);
	const processes = await systemInformation.getHDBProcessInfo();
	for (const { pid } of processes.core) {
		const staleReason = staleHdbPidReason(pid);
		// An unidentified holder may be the Harper to stop, so it is signalled; harper run refuses to start beside it too
		if (staleReason === null) {
			exec(`kill ${pid}`);
			continue;
		}
		const pidFile = path.join(rootPath, hdbTerms.HDB_PID_FILE);
		let message = `Not signalling pid ${pid} from ${pidFile}: it ${staleReason}.`;
		if (removeIfStillNames(pidFile, pid)) message += ' Removed the stale pid file.';
		console.log(message);
		hdbLogger.warn(message);
	}
}

// Only while the file still names that pid, since a Harper starting meanwhile rewrites it with its own
export function removeIfStillNames(pidFile: string, pid: number): boolean {
	try {
		if (Number.parseInt(fs.readFileSync(pidFile, 'utf8'), 10) !== pid) return false;
		fs.rmSync(pidFile);
		return true;
	} catch {
		return false;
	}
}
