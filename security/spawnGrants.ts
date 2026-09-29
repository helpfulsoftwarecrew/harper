import { realpathSync } from 'node:fs';
import { isAbsolute, relative, sep } from 'node:path';

// A component-relative entry in `applications.allowedSpawnCommands`, beside the plain strings.
export interface SpawnGrant {
	component: string;
	path: string;
}
export type SpawnCommandEntry = string | SpawnGrant;

export interface SpawnAllowlist {
	commands: Set<string>;
	grants: Map<string, RegExp[]>;
}

// Structural, so this module need not import ApplicationScope from the loader.
export interface SpawnScope {
	name?: string;
	allowedPath?: string;
	runtimeRoot?: string;
}

/** Why `grantPath` cannot be a grant path, or undefined; config validation and compilation share it. */
export function grantPathProblem(grantPath: string): string | undefined {
	if (grantPath === '') return 'must not be empty';
	if (isAbsolute(grantPath) || grantPath.startsWith('/'))
		return 'must be relative to the component directory, not absolute';
	for (const segment of grantPath.split('/')) {
		if (segment === '') return 'must not contain an empty path segment';
		if (segment === '.' || segment === '..') return `must not contain a "${segment}" path segment`;
	}
	return undefined;
}

/** Regex source for one path segment; `*` becomes `[^/]*`, which cannot cross a separator. */
function segmentPattern(segment: string): string {
	return segment.replace(/[\\^$.*+?()[\]{}|/]/g, (character) => (character === '*' ? '[^/]*' : `\\${character}`));
}

function compileGrant(entry: SpawnGrant): RegExp {
	const { component, path: grantPath } = entry;
	if (typeof component !== 'string' || component === '')
		throw new Error('applications.allowedSpawnCommands grant needs a non-empty "component"');
	if (typeof grantPath !== 'string')
		throw new Error(`applications.allowedSpawnCommands grant for ${component} needs a "path" string`);
	const problem = grantPathProblem(grantPath);
	if (problem) throw new Error(`applications.allowedSpawnCommands path "${grantPath}" for ${component} ${problem}`);
	const source = grantPath.split('/').map(segmentPattern).join('/');
	return new RegExp(`^${source}$`);
}

/** Splits the allowlist into the string Set and grants keyed by component; a malformed grant throws. */
export function compileSpawnAllowlist(entries: readonly SpawnCommandEntry[]): SpawnAllowlist {
	const commands = new Set<string>();
	const grants = new Map<string, RegExp[]>();
	for (const entry of entries) {
		if (typeof entry === 'string') {
			commands.add(entry);
			continue;
		}
		const compiled = compileGrant(entry);
		const forComponent = grants.get(entry.component);
		if (forComponent) forComponent.push(compiled);
		else grants.set(entry.component, [compiled]);
	}
	return { commands, grants };
}

/** `target` relative to `root`, both realpath'd first; undefined when missing, outside `root` or `root` itself. */
export function containedPath(root: string, target: string): string | undefined {
	let resolvedRoot: string;
	let resolvedTarget: string;
	try {
		resolvedRoot = realpathSync(root);
		resolvedTarget = realpathSync(target);
	} catch {
		return undefined;
	}
	const relativePath = relative(resolvedRoot, resolvedTarget);
	if (relativePath === '' || isAbsolute(relativePath)) return undefined;
	const segments = relativePath.split(sep);
	// The whole first segment: `..data`, which Kubernetes volume mounts use, is a child, not a traversal.
	if (segments[0] === '..') return undefined;
	return segments.join('/');
}

/** Whether a grant matches `relativePath`; `[^/]*` matches `..`, so dot segments are refused first. */
export function grantsMatch(grants: readonly RegExp[], relativePath: string): boolean {
	for (const segment of relativePath.split('/')) {
		if (segment === '' || segment === '.' || segment === '..') return false;
	}
	return grants.some((grant) => grant.test(relativePath));
}

/** `token` relative to the scope's component directory, or undefined; only such a token can be granted. */
function grantCandidate(token: string, scope?: SpawnScope): string | undefined {
	// allowedPath is '' unless applications.allowedDirectory is `app`; the loader sets runtimeRoot either way.
	const componentRoot = scope?.runtimeRoot || scope?.allowedPath;
	if (!scope?.name || !componentRoot || !isAbsolute(token)) return undefined;
	return containedPath(componentRoot, token);
}

function isGrantedPath(token: string, allowlist: SpawnAllowlist, scope?: SpawnScope): boolean {
	const grants = scope?.name ? allowlist.grants.get(scope.name) : undefined;
	if (!grants?.length) return false;
	const relativePath = grantCandidate(token, scope);
	return relativePath !== undefined && grantsMatch(grants, relativePath);
}

/** Whether the command's first space-delimited token may spawn; the string Set is tried first. */
export function isSpawnAllowed(command: string, allowlist: SpawnAllowlist, scope?: SpawnScope): boolean {
	const token = command.split(' ')[0];
	if (allowlist.commands.has(token)) return true;
	return isGrantedPath(token, allowlist, scope);
}

/** Opens with `Command <command> is not allowed`, then names the string form and, for a command a grant could admit, the grant form. */
export function spawnRefusalMessage(command: string, scope?: SpawnScope): string {
	const grantForm =
		grantCandidate(command.split(' ')[0], scope) === undefined
			? ''
			: `, or as { component: ${scope?.name}, path: <path under that component's directory> }`;
	return `Command ${command} is not allowed. Add its first token to applications.allowedSpawnCommands as an exact string${grantForm}`;
}
