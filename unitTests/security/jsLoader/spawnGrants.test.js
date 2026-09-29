'use strict';

const assert = require('node:assert');
const { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const {
	compileSpawnAllowlist,
	containedPath,
	grantPathProblem,
	grantsMatch,
	isSpawnAllowed,
	spawnRefusalMessage,
} = require('#src/security/spawnGrants');
const { scopedImport } = require('#src/security/jsLoader');
const { ApplicationScope } = require('#src/components/ApplicationScope');
const env = require('#src/utility/environment/environmentManager');
const { CONFIG_PARAMS } = require('#src/utility/hdbTerms');

const COMPONENT = 'my-component';
const PLATFORM_PACKAGE = '@example/agent-linux-arm64';
const GRANT_PATH = `node_modules/@example/agent-*/bin/agent`;

let root;
let componentDirectory;
let agentBinary;
let siblingAgentBinary;
let nestedAgentBinary;
let shellSymlink;
let binShSymlink;
let entryModule;

// Mirrors an installed component beside a sibling whose name starts with the component's name.
function buildFixture() {
	// Realpath'd as componentLoader does allowedPath, so macOS /var and /private/var cannot disagree.
	root = realpathSync(mkdtempSync(join(tmpdir(), 'harper-spawn-grants-')));
	componentDirectory = join(root, 'components', COMPONENT);
	const binDirectory = join(componentDirectory, 'node_modules', PLATFORM_PACKAGE, 'bin');
	mkdirSync(join(binDirectory, 'nested', 'bin'), { recursive: true });
	agentBinary = join(binDirectory, 'agent');
	writeFileSync(agentBinary, '#!/bin/sh\n');
	// Replays the grant's tail one directory deeper, so only a wildcard spanning `/` reaches it.
	nestedAgentBinary = join(binDirectory, 'nested', 'bin', 'agent');
	writeFileSync(nestedAgentBinary, '#!/bin/sh\n');

	const siblingBin = join(root, 'components', `${COMPONENT}-evil`, 'node_modules', PLATFORM_PACKAGE, 'bin');
	mkdirSync(siblingBin, { recursive: true });
	siblingAgentBinary = join(siblingBin, 'agent');
	writeFileSync(siblingAgentBinary, '#!/bin/sh\n');

	const outsideShell = join(root, 'outside', 'sh');
	mkdirSync(join(root, 'outside'), { recursive: true });
	writeFileSync(outsideShell, '#!/bin/sh\n');
	shellSymlink = join(binDirectory, 'shell');
	symlinkSync(outsideShell, shellSymlink);
	binShSymlink = join(binDirectory, 'system-sh');
	symlinkSync('/bin/sh', binShSymlink);

	// Loaded through the VM loader, so it receives the child_process built for its scope.
	entryModule = join(componentDirectory, 'usesChildProcess.mjs');
	writeFileSync(entryModule, "import * as childProcess from 'node:child_process';\nexport { childProcess };\n");
}

const grantedScope = () => ({ name: COMPONENT, allowedPath: componentDirectory });
const otherScope = () => ({ name: 'harper-other-component', allowedPath: componentDirectory });

describe('spawn grants', () => {
	before(buildFixture);
	after(() => rmSync(root, { recursive: true, force: true }));

	describe('existing string entries', () => {
		it('should allow a bare string entry with no scope, an ungranted scope, and a granted scope', () => {
			const allowlist = compileSpawnAllowlist(['npm', 'node', { component: COMPONENT, path: GRANT_PATH }]);
			for (const scope of [undefined, otherScope(), grantedScope()]) {
				assert.strictEqual(isSpawnAllowed('npm', allowlist, scope), true);
				assert.strictEqual(isSpawnAllowed('node', allowlist, scope), true);
			}
		});

		it('should match a string entry on the first space-delimited token only', () => {
			const allowlist = compileSpawnAllowlist(['npm']);
			assert.strictEqual(isSpawnAllowed('npm install --production', allowlist), true);
			assert.strictEqual(isSpawnAllowed('npminstall', allowlist), false);
		});

		it('should allow an exact absolute string entry, unchanged by a grant on the same component', () => {
			const withGrant = compileSpawnAllowlist([agentBinary, { component: COMPONENT, path: GRANT_PATH }]);
			const withoutGrant = compileSpawnAllowlist([agentBinary]);
			for (const allowlist of [withGrant, withoutGrant]) {
				assert.strictEqual(isSpawnAllowed(agentBinary, allowlist, grantedScope()), true);
				assert.strictEqual(isSpawnAllowed(agentBinary, allowlist, otherScope()), true);
				assert.strictEqual(isSpawnAllowed(agentBinary, allowlist), true);
			}
		});

		it('should refuse a command that is in no string entry and no grant', () => {
			const allowlist = compileSpawnAllowlist(['npm', 'node']);
			assert.strictEqual(isSpawnAllowed('/bin/sh', allowlist, grantedScope()), false);
		});

		it('should refuse everything when the allowlist is empty', () => {
			const allowlist = compileSpawnAllowlist([]);
			assert.strictEqual(isSpawnAllowed('npm', allowlist, grantedScope()), false);
			assert.strictEqual(isSpawnAllowed(agentBinary, allowlist, grantedScope()), false);
		});
	});

	describe('grant matching', () => {
		it('should allow the granted path for the component the grant names', () => {
			const allowlist = compileSpawnAllowlist([{ component: COMPONENT, path: GRANT_PATH }]);
			assert.strictEqual(isSpawnAllowed(agentBinary, allowlist, grantedScope()), true);
		});

		it('should allow the granted path with arguments appended to the command', () => {
			const allowlist = compileSpawnAllowlist([{ component: COMPONENT, path: GRANT_PATH }]);
			assert.strictEqual(isSpawnAllowed(`${agentBinary} --config /etc/agent.yaml`, allowlist, grantedScope()), true);
		});

		it('should keep grants for two components independent', () => {
			const allowlist = compileSpawnAllowlist([
				{ component: COMPONENT, path: GRANT_PATH },
				{ component: 'harper-other-component', path: 'bin/other' },
			]);
			assert.strictEqual(isSpawnAllowed(agentBinary, allowlist, grantedScope()), true);
			assert.strictEqual(isSpawnAllowed(agentBinary, allowlist, otherScope()), false);
		});
	});

	describe('escape routes', () => {
		it('should refuse a grant issued to a different component', () => {
			const allowlist = compileSpawnAllowlist([{ component: COMPONENT, path: GRANT_PATH }]);
			assert.strictEqual(isSpawnAllowed(agentBinary, allowlist, otherScope()), false);
		});

		it('should refuse with no scope, or a scope missing its name or its root', () => {
			const allowlist = compileSpawnAllowlist([{ component: COMPONENT, path: GRANT_PATH }]);
			assert.strictEqual(isSpawnAllowed(agentBinary, allowlist, { allowedPath: componentDirectory }), false);
			assert.strictEqual(isSpawnAllowed(agentBinary, allowlist, { name: COMPONENT }), false);
			assert.strictEqual(isSpawnAllowed(agentBinary, allowlist), false);
		});

		it('should refuse a sibling directory that shares the component name as a prefix', () => {
			const allowlist = compileSpawnAllowlist([{ component: COMPONENT, path: GRANT_PATH }]);
			assert.strictEqual(isSpawnAllowed(siblingAgentBinary, allowlist, grantedScope()), false);
			assert.strictEqual(containedPath(componentDirectory, siblingAgentBinary), undefined);
		});

		it('should refuse an in-component symlink that resolves outside the component directory', () => {
			const allowlist = compileSpawnAllowlist([
				{ component: COMPONENT, path: `node_modules/@example/agent-*/bin/shell` },
			]);
			assert.strictEqual(isSpawnAllowed(shellSymlink, allowlist, grantedScope()), false);
			assert.strictEqual(containedPath(componentDirectory, shellSymlink), undefined);
		});

		it('should refuse an in-component symlink to /bin/sh', () => {
			const allowlist = compileSpawnAllowlist([
				{ component: COMPONENT, path: `node_modules/@example/agent-*/bin/system-sh` },
			]);
			assert.strictEqual(isSpawnAllowed(binShSymlink, allowlist, grantedScope()), false);
		});

		it('should refuse a wildcard match that would cross a path separator', () => {
			const allowlist = compileSpawnAllowlist([{ component: COMPONENT, path: `node_modules/@example/*/bin/agent` }]);
			assert.strictEqual(isSpawnAllowed(agentBinary, allowlist, grantedScope()), true);
			assert.strictEqual(isSpawnAllowed(nestedAgentBinary, allowlist, grantedScope()), false);
		});

		it('should never satisfy a wildcard with a "." or ".." segment', () => {
			const allowlist = compileSpawnAllowlist([{ component: COMPONENT, path: 'bin/*/agent' }]);
			const grants = allowlist.grants.get(COMPONENT);
			assert.strictEqual(grantsMatch(grants, 'bin/x/agent'), true);
			assert.strictEqual(grantsMatch(grants, 'bin/../agent'), false);
			assert.strictEqual(grantsMatch(grants, 'bin/./agent'), false);
			// `[^/]*` alone accepts `..`, so the guard in grantsMatch is what rejects it, not the regex.
			assert.strictEqual(grants[0].test('bin/../agent'), true);
		});

		it('should refuse a target that does not exist', () => {
			const allowlist = compileSpawnAllowlist([{ component: COMPONENT, path: GRANT_PATH }]);
			const missing = join(componentDirectory, 'node_modules', PLATFORM_PACKAGE, 'bin', 'agent-gone');
			assert.strictEqual(isSpawnAllowed(missing, allowlist, grantedScope()), false);
		});

		it('should refuse a relative command token', () => {
			const allowlist = compileSpawnAllowlist([{ component: COMPONENT, path: GRANT_PATH }]);
			assert.strictEqual(isSpawnAllowed(GRANT_PATH.replace('*', 'linux-arm64'), allowlist, grantedScope()), false);
		});

		it('should refuse the component directory itself', () => {
			const allowlist = compileSpawnAllowlist([{ component: COMPONENT, path: GRANT_PATH }]);
			assert.strictEqual(containedPath(componentDirectory, componentDirectory), undefined);
			assert.strictEqual(isSpawnAllowed(componentDirectory, allowlist, grantedScope()), false);
		});

		it('should reject an empty or absolute grant path, or one with an empty, "." or ".." segment', () => {
			for (const bad of ['../other/bin/tool', 'bin/../../other/tool', '/usr/bin/tool', 'bin//tool', './bin/tool', '']) {
				assert.strictEqual(typeof grantPathProblem(bad), 'string', bad);
				assert.throws(() => compileSpawnAllowlist([{ component: COMPONENT, path: bad }]), /allowedSpawnCommands/, bad);
			}
			assert.strictEqual(grantPathProblem(GRANT_PATH), undefined);
		});

		it('should reject a grant with no component name', () => {
			assert.throws(() => compileSpawnAllowlist([{ component: '', path: GRANT_PATH }]), /non-empty "component"/);
		});

		it('should match a "." in a grant path literally', () => {
			const allowlist = compileSpawnAllowlist([{ component: COMPONENT, path: 'bin/a.b' }]);
			const grants = allowlist.grants.get(COMPONENT);
			assert.strictEqual(grants[0].test('bin/a.b'), true);
			assert.strictEqual(grants[0].test('bin/axb'), false);
		});
	});

	describe('refusal message', () => {
		it('should name the grant form only for a command under the component directory', () => {
			const message = spawnRefusalMessage(agentBinary, grantedScope());
			assert.ok(message.includes(`Command ${agentBinary} is not allowed`));
			assert.ok(message.includes('applications.allowedSpawnCommands'));
			assert.ok(message.includes(`component: ${COMPONENT}`));
			for (const command of ['/opt/agent/bin/agent', 'agent', siblingAgentBinary]) {
				assert.ok(!spawnRefusalMessage(command, grantedScope()).includes('component:'), command);
			}
		});

		it('should omit the grant form when there is no component identity', () => {
			const message = spawnRefusalMessage('/bin/sh');
			assert.ok(message.includes('applications.allowedSpawnCommands'));
			assert.ok(!message.includes('component:'));
			assert.ok(!spawnRefusalMessage(agentBinary, { allowedPath: componentDirectory }).includes('component:'));
		});
	});

	// The loader's own wiring, through scopedImport; no test here starts a process.
	describe('constrained child_process', () => {
		const childProcessScope = (name) => ({ mode: 'vm-current-context', name, allowedPath: componentDirectory });
		const importChildProcess = (scope) => scopedImport(entryModule, scope);

		it('should refuse spawn of an unlisted command and name the string and grant forms', async () => {
			const { childProcess } = await importChildProcess(childProcessScope(COMPONENT));
			assert.throws(
				() => childProcess.spawn(agentBinary, { name: 'agent' }),
				(error) =>
					error.message.includes(
						`Command ${agentBinary} is not allowed. Add its first token to applications.allowedSpawnCommands as an exact string, or as { component: ${COMPONENT}, path: <path under that component's directory> }`
					)
			);
		});

		it('should refuse n and npm when the configured value is the string npm', async () => {
			const configured = env.get(CONFIG_PARAMS.APPLICATIONS_ALLOWEDSPAWNCOMMANDS);
			env.setProperty(CONFIG_PARAMS.APPLICATIONS_ALLOWEDSPAWNCOMMANDS, 'npm');
			try {
				const { childProcess } = await importChildProcess(childProcessScope(COMPONENT));
				// Iterated as characters, the string would admit `n`; read as one entry, it would admit `npm`.
				assert.throws(
					() => childProcess.spawn('n', { name: 'agent' }),
					(error) => error.message.includes('Command n is not allowed')
				);
				assert.throws(
					() => childProcess.spawn('npm', { name: 'agent' }),
					(error) => error.message.includes('Command npm is not allowed')
				);
			} finally {
				env.setProperty(CONFIG_PARAMS.APPLICATIONS_ALLOWEDSPAWNCOMMANDS, configured);
			}
		});

		it('should not gate fork on the allowlist', async () => {
			const { childProcess } = await importChildProcess(childProcessScope(COMPONENT));
			// fork launches node, so it carries alwaysAllow; it stops at the process-name check instead.
			assert.throws(() => childProcess.fork('/usr/local/bin/anything'), /must have a process "name"/);
		});

		it('should still refuse execSync outright', async () => {
			const { childProcess } = await importChildProcess(childProcessScope(COMPONENT));
			assert.throws(
				() => childProcess.execSync('ls'),
				(error) => error.message.includes('execSync is not allowed')
			);
		});

		it('should admit a granted binary under allowedDirectory any, where the loader leaves allowedPath empty', async () => {
			const configuredDirectory = env.get(CONFIG_PARAMS.APPLICATIONS_ALLOWEDDIRECTORY);
			const configuredCommands = env.get(CONFIG_PARAMS.APPLICATIONS_ALLOWEDSPAWNCOMMANDS);
			env.setProperty(CONFIG_PARAMS.APPLICATIONS_ALLOWEDDIRECTORY, 'any');
			env.setProperty(CONFIG_PARAMS.APPLICATIONS_ALLOWEDSPAWNCOMMANDS, [{ component: COMPONENT, path: GRANT_PATH }]);
			try {
				const scope = new ApplicationScope(COMPONENT, {}, {});
				// As loadComponent in componentLoader.ts sets both roots on the scope it builds.
				scope.runtimeRoot ??= realpathSync(componentDirectory);
				scope.allowedPath ??= realpathSync(componentDirectory);
				assert.strictEqual(scope.allowedPath, '');
				const { childProcess } = await importChildProcess(scope);
				assert.throws(() => childProcess.spawn(agentBinary), /must have a process "name"/);
			} finally {
				env.setProperty(CONFIG_PARAMS.APPLICATIONS_ALLOWEDDIRECTORY, configuredDirectory);
				env.setProperty(CONFIG_PARAMS.APPLICATIONS_ALLOWEDSPAWNCOMMANDS, configuredCommands);
			}
		});

		it('should give each scope its own constrained child_process', async () => {
			const first = await importChildProcess(childProcessScope(COMPONENT));
			const second = await importChildProcess(childProcessScope('harper-other-component'));
			assert.notStrictEqual(first.childProcess, second.childProcess);
			assert.throws(
				() => second.childProcess.spawn(agentBinary, { name: 'agent' }),
				(error) => error.message.includes('component: harper-other-component')
			);
		});
	});
});
