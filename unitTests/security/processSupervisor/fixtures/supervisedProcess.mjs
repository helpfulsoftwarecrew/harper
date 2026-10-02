// A supervised child for the supervision matrix. Given a marker path it dies once with the given code
// and every later incarnation runs until signalled, so a restart is observable without an endless loop.
import { existsSync, writeFileSync } from 'node:fs';

// Flags after these, such as the lock a stand-in reaper carries, name it and are not its own arguments
const own = process.argv.slice(2);
const flag = own.findIndex((argument) => argument.startsWith('--'));
const [marker, code] = flag === -1 ? own : own.slice(0, flag);
if (marker && !existsSync(marker)) {
	writeFileSync(marker, String(process.pid));
	process.exit(Number.parseInt(code, 10));
}
setInterval(() => {}, 1 << 30);
