/** Per-record expiry jitter, so records cached in the same instant stop expiring together. Off by default. */

import type { EventLoopUtilization } from 'node:perf_hooks';

/** Jitter runs on every write, so a sample is reused for a second by every table on the thread. */
const UTILIZATION_SAMPLE_INTERVAL_MS = 1000;

let lastSampleTime = -Infinity;
let lastCumulativeELU: EventLoopUtilization | undefined;
let cachedUtilization = 1;

/** Event loop utilization in [0,1] since the previous sample, or since the loop started; 1 with no reader. */
export function eventLoopUtilization(): number {
	const readELU = (performance as any).eventLoopUtilization;
	if (!readELU) return 1;
	const now = performance.now();
	if (now - lastSampleTime < UTILIZATION_SAMPLE_INTERVAL_MS) return cachedUtilization;
	lastSampleTime = now;
	const cumulative = readELU.call(performance);
	// The lifetime-cumulative reading converges on a constant, so diff against the previous sample.
	const recent = lastCumulativeELU ? readELU.call(performance, cumulative, lastCumulativeELU) : cumulative;
	lastCumulativeELU = cumulative;
	cachedUtilization = utilizationOf(recent);
	return cachedUtilization;
}

/**
 * A reading's utilization clamped to [0,1]. A missing reading, or one that covers no time (Bun's always
 * does), counts as 1, not 0, so opt-in jitter stays on.
 */
export function utilizationOf(reading: EventLoopUtilization | undefined): number {
	const measured = reading?.idle + reading?.active > 0 && Number.isFinite(reading.utilization);
	return measured ? Math.min(Math.max(reading.utilization, 0), 1) : 1;
}

/** A record's fixed place in the jitter window, in [0,1), so it keeps that place across refreshes. */
export function perRecordSpread(id: unknown): number {
	const key = typeof id === 'string' ? id : String(id);
	let hash = 0x811c9dc5;
	for (let i = 0; i < key.length; i++) {
		hash = Math.imul(hash ^ key.charCodeAt(i), 0x01000193);
	}
	// Plain FNV-1a leaves adjacent numeric ids in adjacent buckets, which would re-synchronize the herd.
	hash ^= hash >>> 16;
	hash = Math.imul(hash, 0x7feb352d);
	hash ^= hash >>> 15;
	return (hash >>> 0) / 0x100000000;
}

/**
 * Ms to add to a computed expiry: load opens the window, the id places the record inside it. Keep
 * both terms; a load-only value shifts every record by the same amount and the herd stays in phase.
 */
export function expirationJitter(id: unknown, maxJitterMs: number, utilization?: number): number {
	// Most TTL tables have jitter off; a default parameter for utilization would sample the loop first.
	if (!(maxJitterMs > 0)) return 0;
	return Math.round(maxJitterMs * (utilization ?? eventLoopUtilization()) * perRecordSpread(id));
}

/**
 * Coerce a `jitter` directive value to a max delay in ms; `false`/`null`/`undefined` mean off.
 * Milliseconds, not seconds: a one-second floor would be useless inside a short TTL.
 */
export function normalizeJitter(jitter: unknown): number {
	if (jitter == null || jitter === false || jitter === 'false') return 0;
	if (jitter === true || jitter === 'true')
		throw new Error('Jitter must be false or a maximum delay in milliseconds, not true');
	const max = Number(jitter);
	if (!Number.isFinite(max)) throw new Error(`Invalid jitter value: ${String(jitter)}`);
	if (max < 0) throw new Error('Jitter can not be negative');
	return Math.round(max);
}
