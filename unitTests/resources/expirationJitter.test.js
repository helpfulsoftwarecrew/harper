require('../testUtils');
const assert = require('assert');
const { setTimeout: delay } = require('timers/promises');
const { setupTestDBPath } = require('../testUtils');
const { table } = require('#src/resources/databases');
const { loadGQLSchema } = require('#src/resources/graphql');
const { Resource } = require('#src/resources/Resource');
const { setMainIsWorker } = require('#js/server/threads/manageThreads');
const { waitFor } = require('../waitFor.js');
const {
	expirationJitter,
	perRecordSpread,
	normalizeJitter,
	eventLoopUtilization,
	utilizationOf,
} = require('#src/resources/expirationJitter');

// Ids cached in the same instant: the herd the jitter has to pull apart.
const HERD_IDS = Array.from({ length: 15 }, (_, i) => `product-${i + 1}`);

/** Keep the loop busy for `ms` so the utilization sampler reads a loaded thread. */
async function saturateEventLoop(ms) {
	eventLoopUtilization(); // re-baselines only if the sampler last read the loop a second or more ago
	const end = Date.now() + ms;
	while (Date.now() < end) {
		const chunk = Date.now();
		while (Date.now() - chunk < 20) {}
		await delay(0);
	}
}

describe('Expiration jitter', () => {
	it('is off unless a maximum is configured', function () {
		for (const id of HERD_IDS) {
			assert.strictEqual(expirationJitter(id, 0), 0);
			assert.strictEqual(expirationJitter(id, undefined), 0);
			assert.strictEqual(expirationJitter(id, false), 0);
		}
	});

	it('adds nothing on an idle thread', function () {
		for (const id of HERD_IDS) assert.strictEqual(expirationJitter(id, 5000, 0), 0);
	});

	it('never exceeds the configured maximum and is never negative', function () {
		for (const utilization of [0, 0.01, 0.25, 0.5, 1]) {
			for (const id of HERD_IDS) {
				const jitter = expirationJitter(id, 5000, utilization);
				assert(jitter >= 0 && jitter <= 5000, `jitter ${jitter} outside [0,5000] for ${id}`);
			}
		}
	});

	it('varies per record at a fixed system load', function () {
		const jitters = HERD_IDS.map((id) => expirationJitter(id, 5000, 1));
		assert.strictEqual(new Set(jitters).size, HERD_IDS.length, `not per-record: ${jitters.join(',')}`);
		assert(Math.max(...jitters) - Math.min(...jitters) > 2500, `window barely used: ${jitters.join(',')}`);
	});

	it('places a record at the same point in the window on every refresh', function () {
		for (const id of HERD_IDS) {
			assert.strictEqual(expirationJitter(id, 5000, 1), expirationJitter(id, 5000, 1));
		}
	});

	it('scales the window with system load rather than the record', function () {
		for (const id of HERD_IDS) {
			assert(expirationJitter(id, 5000, 0.25) <= 1250);
			assert(expirationJitter(id, 5000, 0.5) <= 2500);
		}
	});

	it('spreads adjacent numeric ids across the window', function () {
		const spreads = Array.from({ length: 15 }, (_, i) => perRecordSpread(i + 1));
		for (const spread of spreads) assert(spread >= 0 && spread < 1, `spread ${spread} outside [0,1)`);
		assert(Math.min(...spreads) < 0.2, `no ids near the start of the window: ${spreads.join(',')}`);
		assert(Math.max(...spreads) > 0.8, `no ids near the end of the window: ${spreads.join(',')}`);
	});

	it('reads a load figure in [0,1]', function () {
		const utilization = eventLoopUtilization();
		assert(utilization >= 0 && utilization <= 1, `utilization ${utilization} outside [0,1]`);
	});

	it('reads a runtime whose readings cover no time as fully busy', function () {
		assert.strictEqual(utilizationOf({ idle: 0, active: 0, utilization: 0 }), 1);
		assert.strictEqual(utilizationOf(undefined), 1);
		assert.strictEqual(utilizationOf({ idle: 500, active: 500, utilization: 0.5 }), 0.5);
	});

	it('treats false, null and 0 as off, and rejects values that cannot be a maximum', function () {
		assert.strictEqual(normalizeJitter(false), 0);
		assert.strictEqual(normalizeJitter('false'), 0);
		assert.strictEqual(normalizeJitter(null), 0);
		assert.strictEqual(normalizeJitter(undefined), 0);
		assert.strictEqual(normalizeJitter(0), 0);
		assert.strictEqual(normalizeJitter(5000), 5000);
		assert.throws(() => normalizeJitter(true), /not true/);
		assert.throws(() => normalizeJitter(-1), /negative/);
		assert.throws(() => normalizeJitter('sometimes'), /Invalid jitter/);
	});
});

describe('Expiration jitter on tables', () => {
	before(function () {
		setupTestDBPath();
		setMainIsWorker(true);
	});

	const makeTable = (name, options) =>
		table({
			table: name,
			database: 'test',
			...options,
			attributes: [{ name: 'id', isPrimaryKey: true }, { name: 'name' }],
		});

	const storedExpiresAt = async (Table, id) => {
		await Table.primaryStore.committed;
		return Table.primaryStore.getEntry(id)?.expiresAt;
	};

	/** Write every id and return, per id, the stored expiry minus the instant it was written. */
	async function writeAll(Table, ids) {
		const offsets = new Map();
		for (const id of ids) {
			const writtenAt = Date.now();
			await Table.put(id, { id, name: id });
			offsets.set(id, { writtenAt, elapsed: Date.now() - writtenAt });
		}
		for (const id of ids) {
			offsets.get(id).expiresAt = await storedExpiresAt(Table, id);
		}
		return offsets;
	}

	// Unjittered expiry is both the contract jitter:false keeps and the herd itself, so the bounds are tight.
	function assertUnjittered(offsets) {
		for (const [id, { writtenAt, elapsed, expiresAt }] of offsets) {
			assert(
				expiresAt >= writtenAt + 30_000 && expiresAt <= writtenAt + elapsed + 30_000,
				`${id} expiry ${expiresAt - writtenAt}ms out, expected exactly 30000ms plus write time`
			);
		}
	}

	it('leaves expiry untouched when jitter is off', async function () {
		const offsets = await writeAll(makeTable('JitterOff', { expiration: 30 }), HERD_IDS);
		assertUnjittered(offsets);
		const expiries = [...offsets.values()].map((o) => o.expiresAt);
		assert(Math.max(...expiries) - Math.min(...expiries) < 1000, 'unjittered batch should expire together');
	});

	it('leaves expiry untouched when jitter is explicitly false', async function () {
		const Table = makeTable('JitterFalse', { expiration: 30, jitter: false });
		assert.strictEqual(Table.jitterMS, 0);
		assertUnjittered(await writeAll(Table, HERD_IDS));
	});

	it('spreads a batch written in the same instant when jitter is on', async function () {
		const Table = makeTable('JitterOn', { expiration: 30, jitter: 5000 });
		assert.strictEqual(Table.jitterMS, 5000);
		await saturateEventLoop(1500);
		const offsets = await writeAll(Table, HERD_IDS);
		const jitters = [...offsets.values()].map(({ writtenAt, elapsed, expiresAt }) => {
			const jitter = expiresAt - writtenAt - 30_000;
			assert(jitter >= 0 && jitter <= 5000 + elapsed, `jitter ${jitter} outside [0,5000]`);
			return Math.round(jitter / 100); // bucket away the millisecond of write time between puts
		});
		assert(new Set(jitters).size >= 10, `records did not spread: ${jitters.join(',')}`);
		assert(Math.max(...jitters) - Math.min(...jitters) >= 5, `spread under 500ms: ${jitters.join(',')}`);
	});

	it('does not turn the no-expiration sentinel into an expiry', async function () {
		const Table = makeTable('JitterSentinel', { jitter: 5000, scanInterval: 3600 });
		await Table.put('sentinel', { id: 'sentinel', name: 'forever' });
		assert.strictEqual(await storedExpiresAt(Table, 'sentinel'), undefined);
	});

	it('does not jitter an explicitly supplied expiresAt', async function () {
		const Table = makeTable('JitterExplicit', { expiration: 30, jitter: 5000 });
		await saturateEventLoop(1200);
		const explicit = Date.now() + 60_000;
		await Table.put('explicit', { id: 'explicit', name: 'pinned' }, { expiresAt: explicit });
		assert.strictEqual(await storedExpiresAt(Table, 'explicit'), explicit);
	});

	it('replaces a configured maximum when setTTLExpiration is called again', function () {
		const Table = makeTable('JitterReplace', { expiration: 30, jitter: 5000 });
		assert.strictEqual(Table.jitterMS, 5000);
		Table.setTTLExpiration({ expiration: 30 });
		assert.strictEqual(Table.jitterMS, 0);
		Table.setTTLExpiration({ expiration: 30, jitter: 250 });
		assert.strictEqual(Table.jitterMS, 250);
		assert.throws(() => Table.setTTLExpiration({ expiration: 30, jitter: -1 }), /negative/);
	});

	it('keeps the loaded TTL when a redeclaration sets jitter to false or 0', function () {
		const attributes = () => [
			{ name: 'id', isPrimaryKey: true },
			{ name: 'expiresAt', expiresAt: true, indexed: true },
		];
		for (const [name, jitter] of [
			['JitterRedeclareFalse', false],
			['JitterRedeclareZero', 0],
		]) {
			table({ table: name, database: 'test', expiration: 30, attributes: attributes() });
			const Table = table({ table: name, database: 'test', jitter, attributes: attributes() });
			assert.strictEqual(Table.expirationMS, 30_000);
			assert.strictEqual(Table.jitterMS, 0);
		}
	});
});

describe('Expiration jitter on cache refresh', () => {
	if (process.env.HARPER_STORAGE_ENGINE === 'lmdb') return; // matches the other caching tests, harper#414

	before(function () {
		setupTestDBPath();
		setMainIsWorker(true);
	});

	const makeCache = (name, options, source) => {
		const Table = table({
			table: name,
			database: 'test',
			attributes: [{ name: 'id', isPrimaryKey: true }, { name: 'name' }],
		});
		Table.sourcedFrom(source, options);
		return Table;
	};

	const PlainSource = class extends Resource {
		get() {
			return { id: this.getId(), name: 'from source' };
		}
	};

	// A source fill returns before its cache write commits, so poll the store rather than read it once.
	async function fillAndReadExpiries(Table, ids) {
		for (const id of ids) await Table.get(id);
		await waitFor(() => ids.every((id) => Table.primaryStore.getEntry(id)?.expiresAt != undefined));
		return ids.map((id) => Table.primaryStore.getEntry(id).expiresAt);
	}

	it('spreads records refreshed from a source in the same instant', async function () {
		const Table = makeCache('JitterSourced', { expiration: 30, eviction: 300, jitter: 5000 }, PlainSource);
		assert.strictEqual(Table.jitterMS, 5000);
		await saturateEventLoop(1500);
		const filledAt = Date.now();
		const jitters = (await fillAndReadExpiries(Table, HERD_IDS)).map((expiresAt) =>
			Math.round((expiresAt - filledAt - 30_000) / 100)
		);
		assert(new Set(jitters).size >= 10, `refreshes did not spread: ${jitters.join(',')}`);
		assert(Math.max(...jitters) - Math.min(...jitters) >= 5, `spread under 500ms: ${jitters.join(',')}`);
	});

	it('refreshes a batch together when jitter is off', async function () {
		const Table = makeCache('JitterSourcedOff', { expiration: 30, eviction: 300 }, PlainSource);
		const filledAt = Date.now();
		const expiries = await fillAndReadExpiries(Table, HERD_IDS);
		for (const expiresAt of expiries) assert(expiresAt >= filledAt + 30_000);
		assert(Math.max(...expiries) - Math.min(...expiries) < 1000, 'unjittered refresh should stay in phase');
	});

	it('does not jitter an expiry the source set itself', async function () {
		const pinned = Date.now() + 120_000;
		const PinningSource = class extends Resource {
			get() {
				this.getContext().expiresAt = pinned;
				return { id: this.getId(), name: 'pinned by source' };
			}
		};
		const Table = makeCache('JitterSourcePinned', { expiration: 30, jitter: 5000 }, PinningSource);
		await saturateEventLoop(1200);
		await Table.get('pinned-1');
		const expiresAt = await waitFor(() => Table.primaryStore.getEntry('pinned-1')?.expiresAt);
		assert.strictEqual(expiresAt, pinned);
	});
});

describe('Expiration jitter from a GraphQL @table directive', () => {
	before(async function () {
		setupTestDBPath();
		await loadGQLSchema(`
			type JitteredCatalog @table(expiration: 30, eviction: 300, jitter: 5000) {
				id: ID @primaryKey
				name: String
			}
			type UnjitteredCatalog @table(expiration: 30, eviction: 300) {
				id: ID @primaryKey
				name: String
			}
			type FalseJitterCatalog @table(expiration: 30, jitter: false) {
				id: ID @primaryKey
				name: String
			}
		`);
	});

	it('carries the maximum from the directive through to the table', function () {
		assert.strictEqual(tables.JitteredCatalog.jitterMS, 5000);
	});

	it('leaves a table that does not ask for it at zero', function () {
		assert.strictEqual(tables.UnjitteredCatalog.jitterMS, 0);
	});

	it('reads jitter: false as off', function () {
		assert.strictEqual(tables.FalseJitterCatalog.jitterMS, 0);
	});
});
