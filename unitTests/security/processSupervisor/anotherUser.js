'use strict';

// Linux's answers about another user's process, stubbed for one pid so the rule runs on any platform.
// Only a module that reads fs.readlinkSync at call time sees the stub; the reaper destructures it at load.

const fs = require('node:fs');
const { syncBuiltinESMExports } = require('node:module');

function refusal(code, syscall) {
	return Object.assign(new Error(`${code}: operation not permitted, ${syscall}`), { code, syscall });
}

/**
 * Runs `callback` as Linux, where `pid` answers kill() and a read of its exe link with the given
 * errno codes and `exe` names other pids' executables; resolves with the result and the signals `pid` got.
 *
 * @param {{ pid: number, kill?: string, readlink?: string, exe?: Record<number, string> }} stub
 * @param {() => unknown} callback
 */
async function asAnotherUser({ pid, kill, readlink, exe = {} }, callback) {
	const platform = Object.getOwnPropertyDescriptor(process, 'platform');
	const realKill = process.kill;
	const realReadlink = fs.readlinkSync;
	const signals = [];
	Object.defineProperty(process, 'platform', { ...platform, value: 'linux' });
	process.kill = function (target, signal) {
		if (target === pid && kill) {
			if (signal !== 0) signals.push(signal ?? 'SIGTERM');
			throw refusal(kill, 'kill');
		}
		if (target === pid && signal !== 0) signals.push(signal ?? 'SIGTERM');
		return realKill.call(process, target, signal);
	};
	fs.readlinkSync = function (path, ...rest) {
		if (path === `/proc/${pid}/exe` && readlink) throw refusal(readlink, 'readlink');
		const match = /^\/proc\/(\d+)\/exe$/.exec(String(path));
		if (match && exe[Number(match[1])]) return exe[Number(match[1])];
		return realReadlink.call(fs, path, ...rest);
	};
	syncBuiltinESMExports();
	try {
		return { result: await callback(), signals };
	} finally {
		Object.defineProperty(process, 'platform', platform);
		process.kill = realKill;
		fs.readlinkSync = realReadlink;
		syncBuiltinESMExports();
	}
}

module.exports = { asAnotherUser };
