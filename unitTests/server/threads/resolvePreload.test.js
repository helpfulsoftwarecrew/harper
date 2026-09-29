'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { resolvePreloadModules } = require('#src/server/threads/resolvePreload');

describe('resolvePreloadModules', () => {
	let tmpDir;
	let componentsRoot;
	let pkgIndex;
	let pkgInit;
	let scopedMain;
	let scopedPreload;
	let mainOnlyEntry;

	// Lay down a components root with one component that bundles a fake APM package,
	// mirroring how an installed component vendors an instrumentation dependency.
	before(() => {
		tmpDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'preload-test-')));
		componentsRoot = path.join(tmpDir, 'components');
		const pkgDir = path.join(componentsRoot, 'apm-component', 'node_modules', 'fake-apm');
		fs.mkdirSync(pkgDir, { recursive: true });
		pkgIndex = path.join(pkgDir, 'index.js');
		pkgInit = path.join(pkgDir, 'init.js');
		fs.writeFileSync(pkgIndex, 'module.exports = {};\n');
		fs.writeFileSync(pkgInit, 'module.exports = {};\n');

		// The on-disk shape of a deployed component: config-key folder, real scoped name in package.json.
		const scopedDir = path.join(componentsRoot, 'my-component');
		fs.mkdirSync(scopedDir, { recursive: true });
		fs.writeFileSync(
			path.join(scopedDir, 'package.json'),
			JSON.stringify({
				name: '@example/agent',
				exports: { '.': './main.js', './preload': './preload.js' },
			})
		);
		scopedMain = path.join(scopedDir, 'main.js');
		scopedPreload = path.join(scopedDir, 'preload.js');
		fs.writeFileSync(scopedMain, 'module.exports = {};\n');
		fs.writeFileSync(scopedPreload, 'module.exports = {};\n');
		fs.writeFileSync(path.join(scopedDir, 'internal.js'), 'module.exports = {};\n');

		const mainOnlyDir = path.join(componentsRoot, 'main-only');
		fs.mkdirSync(mainOnlyDir, { recursive: true });
		fs.writeFileSync(
			path.join(mainOnlyDir, 'package.json'),
			JSON.stringify({ name: 'main-only-pkg', main: './entry.js' })
		);
		mainOnlyEntry = path.join(mainOnlyDir, 'entry.js');
		fs.writeFileSync(mainOnlyEntry, 'module.exports = {};\n');

		// A config key that collides with the installed `fake-apm` package name.
		const shadowDir = path.join(componentsRoot, 'fake-apm');
		fs.mkdirSync(shadowDir, { recursive: true });
		fs.writeFileSync(
			path.join(shadowDir, 'package.json'),
			JSON.stringify({ name: 'shadow-pkg', exports: { '.': './shadow.js' } })
		);
		fs.writeFileSync(path.join(shadowDir, 'shadow.js'), 'module.exports = {};\n');
	});

	after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

	it('returns an empty array when unconfigured', () => {
		assert.deepEqual(resolvePreloadModules(null, componentsRoot), []);
	});

	it('resolves a bare package specifier from an installed component', () => {
		assert.deepEqual(resolvePreloadModules('fake-apm', componentsRoot), [pkgIndex]);
	});

	it('resolves a package subpath specifier (e.g. dd-trace/init)', () => {
		assert.deepEqual(resolvePreloadModules('fake-apm/init', componentsRoot), [pkgInit]);
	});

	it('accepts an array of specifiers, preserving order', () => {
		assert.deepEqual(resolvePreloadModules(['fake-apm', 'fake-apm/init'], componentsRoot), [pkgIndex, pkgInit]);
	});

	it('resolves an absolute path, applying extension resolution', () => {
		const extensionless = pkgIndex.replace(/\.js$/, '');
		assert.deepEqual(resolvePreloadModules(extensionless, componentsRoot), [pkgIndex]);
	});

	it('skips an unresolvable specifier without throwing', () => {
		assert.deepEqual(resolvePreloadModules(['does-not-exist', 'fake-apm'], componentsRoot), [pkgIndex]);
	});

	it('ignores non-string entries in an array', () => {
		assert.deepEqual(resolvePreloadModules(['fake-apm', 42, null, ''], componentsRoot), [pkgIndex]);
	});

	it('rejects relative-path specifiers (non-deterministic resolution)', () => {
		assert.deepEqual(resolvePreloadModules('./fake-apm/index.js', componentsRoot), []);
	});

	it('does not throw when the components root is missing or unreadable', () => {
		assert.deepEqual(resolvePreloadModules(pkgIndex, path.join(tmpDir, 'no-such-dir')), [pkgIndex]);
	});

	it('resolves the same regardless of the configKey label (preload vs preloadRequire)', () => {
		assert.deepEqual(resolvePreloadModules('fake-apm', componentsRoot, 'threads.preloadRequire'), [pkgIndex]);
	});

	describe('component config-key specifiers', () => {
		it('resolves <key>/<subpath> through the component exports map', () => {
			assert.deepEqual(resolvePreloadModules('my-component/preload', componentsRoot), [scopedPreload]);
		});

		it('resolves a bare key to the component entry point', () => {
			assert.deepEqual(resolvePreloadModules('my-component', componentsRoot), [scopedMain]);
		});

		it('resolves a bare key through package.json `main` when there is no exports map', () => {
			assert.deepEqual(resolvePreloadModules('main-only', componentsRoot), [mainOnlyEntry]);
		});

		it('resolves <key>/<subpath> by path when there is no exports map', () => {
			assert.deepEqual(resolvePreloadModules('main-only/entry.js', componentsRoot), [mainOnlyEntry]);
		});

		it('refuses a subpath the exports map does not export, as the package name does', () => {
			const specifiers = ['my-component/internal.js', 'my-component/internal', '@example/agent/internal.js'];
			assert.deepEqual(resolvePreloadModules(specifiers, componentsRoot), []);
		});

		it('keeps resolving the full package name, so existing configs are untouched', () => {
			assert.deepEqual(resolvePreloadModules('@example/agent/preload', componentsRoot), [scopedPreload]);
		});

		it('lets standard resolution win when a key collides with an installed package name', () => {
			assert.deepEqual(resolvePreloadModules('fake-apm', componentsRoot), [pkgIndex]);
		});

		it('skips an unknown key without throwing, like any unresolvable specifier', () => {
			assert.deepEqual(resolvePreloadModules(['no-such-component/preload', 'my-component/preload'], componentsRoot), [
				scopedPreload,
			]);
		});
	});
});
