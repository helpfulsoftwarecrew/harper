'use strict';

// What the supervisor's suites share beside reaping: a logger that keeps its lines, and the timing and module paths
// every worker-thread suite hands its threads.

/** The shipped timing scaled down, which each suite sets in its own modules and each worker in its own. */
const TEST_TIMING = Object.freeze({ respawnBaseMs: 50, rejoinPollMs: 10, rejoinGraceMs: 750 });

/** The modules a worker thread requires by path, since a thread cannot resolve the `#src` import map itself. */
const WORKER_MODULES = Object.freeze({
	envPath: require.resolve('#src/utility/environment/environmentManager'),
	termsPath: require.resolve('#src/utility/hdbTerms'),
	lifecyclePath: require.resolve('#src/security/processSupervisor/sidecarLifecycle'),
	wrapperPath: require.resolve('#src/security/processSupervisor/adoptionWrapper'),
	lockModulePath: require.resolve('#src/security/processSupervisor/pidFileLock'),
});

function collectingLogger() {
	const lines = { info: [], warn: [], error: [] };
	return {
		lines,
		info: (message) => lines.info.push(String(message)),
		warn: (message) => lines.warn.push(String(message)),
		error: (message) => lines.error.push(String(message)),
	};
}

module.exports = { TEST_TIMING, WORKER_MODULES, collectingLogger };
