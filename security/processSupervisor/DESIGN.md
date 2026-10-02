# security/processSupervisor/ — Sidecar lifecycle (`scope.processes`)

Design notes for the sidecar process machinery behind `scope.processes`, in the style of
`../../resources/DESIGN.md`. The author-facing reference documentation lives in the separate
documentation repo (docs.harperdb.io); this file is the in-repo source of truth for the
mechanism and its invariants until that page exists.

## What a component author writes

A component that needs a real OS process beside it (a metrics exporter, or any other supervised
binary) starts it from `handleApplication(scope)`:

```js
export function handleApplication(scope) {
	scope.processes.start({
		name: 'metrics-agent', // PID-lock filename under <rootPath>/pids
		command: '/opt/metrics-agent/bin/agent', // gated by applications.allowedSpawnCommands
		args: ['run', '-c', configPath],
		fingerprint: [configText, apiKey], // changed inputs replace the running process
		configFiles: { [configPath]: configText }, // written atomically
		verify: async (state) => ({ ok: await probesAnswer(), detail: `pid ${state.pid}` }),
	});
}
```

No `child_process` import, no handling of the many-threads problem: however many worker threads
load the component, the node runs one process per `name`. On Linux and darwin each runs under a
keeper (The keeper), which also identifies it through an exec. `start()` resolves to a
`SidecarState`; `scope.processes.states` keeps one per started descriptor.

Descriptor fields beyond the example: `title` (how messages name it), `exitHint` (appended to
non-zero-exit reports), `script` (required when `command` is an interpreter), `reaper: false`
(skip the detached reaper).

## What start() does, in order

1. **Config writes**, temp-then-rename, so a rereading process never sees a torn file.
2. **Spawn through the identity-checked PID lock** (`constrainedChildProcess.ts`, over the lock in
   `pidFileLock.ts`): the lock asks
   "is this pid running that binary", not "does something hold this number". The winning thread
   launches a keeper on Linux and darwin (The keeper), which starts the process and commits its
   pid; on Windows the thread starts it itself. Every other thread receives an adoption wrapper,
   whose one-second poll is its notice that the process died; `unref()` releases the event loop
   without stopping that poll, and the poll reads the process state rather than only
   `kill(pid, 0)`, so a corpse nothing reaps is not read as alive (Linux every poll; darwin every
   tenth, where that read forks `ps`). A `fingerprint` change moves the lock version, and the
   version-mismatch restart signals only a positively identified process, Windows aside (The one
   signalling rule).
3. **Record the descriptor** (`<name>.sidecar.json` beside the lock, via
   `security/processSupervisor/sidecarRegistry.ts`): name, lock path, spawn-time pid and its start
   time, command, and `script` when there is one. This is what outlives the spawning thread; the
   shutdown path and the reaper act from it.
4. **Ensure the reaper** (below), before `verify` so a node killed during a slow verify does
   not orphan the child. On Linux and darwin it runs under a keeper as a sidecar does.
5. **Verify**, when given; the verdict lands on the state, along with the pid it was taken against.
   A restart re-verifies, because the supervisor rewrites `pid` on that same state object and a verdict
   beside it would go on describing the process that died. `#verify` clears `verified` and `verifyDetail`
   when it stamps `verifiedPid`, so the state reads unverified until the new proof answers, and it drops
   a proof whose stamp a later restart has replaced. A reader comparing `verifiedPid` with `pid` detects a
   restart that could not spawn, where `pid` is cleared.

## The keeper

Node reaps a child, and delivers its `exit`, only on the event loop of the thread that spawned it.
Once that worker thread ends, a child it started dies into a zombie of the node, its exit status
reaches nobody, and a crash with no other thread watching is never restarted. So on Linux and
darwin `scope.processes` starts each process under `sidecarKeeper.js`, run by bare node from its
path as the reaper is:

- The thread's claim on the lock carries a random token and the thread's own start time. It spawns
  `node sidecarKeeper.js --launch ... -- <command> <args>`, which starts the keeper and exits at
  once; the thread reaps that launcher and init adopts the keeper. Not detached, so the keeper
  and its process stay in the node's process group.
- The keeper spawns the process, reads its start time, and inside the lock's gate, only while
  the lock still carries its token, commits `<pid>\n<version>\n<record>`: the record is JSON
  naming the token, the host, the keeper, the keeper's leading command line (which names the lock
  and the token) and the start time. Readers that take the first two lines read it as before.
- On each death the keeper reaps the process and writes `<name>.pid.exit` by temp and rename,
  inside the gate before any release. A stop signal it received, or the process's own SIGTERM,
  SIGINT, SIGHUP or clean exit, is deliberate: it releases the lock and ends. A lock that no
  longer carries its token ends it. Past `RESPAWN_MAX_ATTEMPTS` it releases and gives up.
  Otherwise it records `restarting`, waits the backoff and starts the process again.
- The record is the lock holder's. A keeper writes it only while its lock is gone or still carries
  its token, so one whose lock another took writes nothing over the record of the keeper that took it.

Every thread, the launching one included, watches the pid and answers a death from that record. It
rejoins a restart and re-verifies; a deliberate stop, or a process the keeper gave up on, it reports
as not running, with no pid and no verdict, and leaves alone. A death with no record whose keeper is
gone is not restarted, since nothing can read an orphan's exit status and it may have been a stop.
A death with no record beside a lock that carries another token is the taker's, and the thread joins
what that one starts. A lock that records no keeper keeps the path Windows takes (Invariants worth keeping). A thread
waiting out a keeper's backoff looks at the lock every 50 ms, since each look forks `ps` on darwin.

Identity follows the keeper. A recorded start time decides both ways: a pid that started then is
that process whatever it now runs, since an exec keeps the start time, and a pid that reads another
start time is a reused one, however well its binary matches (Linux reads field 22 of
`/proc/<pid>/stat` with the boot's id, darwin `ps -o lstart=` in the C locale and UTC). Both sides take
that read from one function, the keeper's `inspect`, which `processIdentity.ts` calls with its own `ps`. A
command line is read on darwin under a UTF-8 `LC_CTYPE` with none of the caller's locale variables, since in
the C locale, a launchd service's default, `ps` escapes every byte outside ASCII and a process started from
such a path would read as another program. A recorded
start time that cannot be read now says nothing either way, so it leaves the process "cannot tell" at
worst. Without one, a pid whose parent is the keeper its lock records is vouched for while that
keeper's command line leads with this lock and token; pid 1 and another lock's keeper vouch for
nothing. On darwin a `ps` that times out fails the rest of that identification at once, so a hung one
costs an identification inside the lock's gate one timeout rather than one per read, and the next
identification asks `ps` afresh. A keeper never identifies as a sidecar, even one whose script it
carries in its arguments. The reaper's lock identifies a holder only when it carries `--self-pid-file` for this
lock, so another root's reaper is neither adopted nor signalled.

A claim a keeper has not yet committed is told from one a dead node left by the same start time: a
claimant pid that is gone, or that a later process now holds, as a container restart under the same
pid leaves it, is taken at once. A claim naming this process at its own start is a sibling thread's
and is waited on until the claim itself is 30 seconds old, by its file's modification time, whatever
the caller has waited; then it is taken over, and a keeper that commits under it afterwards finds its
token gone. The gate file names its holder's pid, start time and a nonce of that holding the same way:
a gate left by an earlier process under this pid is broken at once, a live holder's once it is 30
seconds old, and a holder releases the gate only while it still carries its nonce. A thread breaks a
gate only while it holds a second file beside it, `<name>.pid.claiming.breaking`, linked the same way
and broken by the same rules, and judges the gate again once it holds that file, so it never removes a
gate a sibling linked after the one it first read. No test reaches that second judgement, in
`pidFileLock.ts` or in the keeper's copy: a case needs a thread stalled between its first read of the
gate and its break, which only a `ps` shim on darwin gave, and the suite keeps no darwin-only shim
cases. A holder stalled until its gate was broken reads its nonce again right before its write, and
writes nothing once the gate is no longer its own. A caller throws only after twice that age, since
every claim and gate it waits on is abandoned by its own age before. The constrained spawn writes its
pid over its claim inside the gate and only while the claim carries its token. A spawn with no pid
gives the claim back and returns the child, whose `error` says why; `scope.processes` reports that
start as not started, with the error, and the next start tries again. A spawn whose claim was taken or
removed before its write stops the child it started, with SIGKILL five seconds after a SIGTERM that
did not end it, and throws.

## The one signalling rule

Nothing on this path signals a process without positive identification
(`security/processSupervisor/processIdentity.ts`): the pid must demonstrably run the expected command,
or carry the start time its keeper recorded (The keeper), which settles every case below for a
process under a keeper. "Not ours" and "cannot tell" are different answers, and both forbid the
signal. A bare command
name resolves to no path to compare, so it answers "cannot tell" on every platform (on darwin so
does a process started by bare name). On Linux so does a process whose binary was replaced on
disk, since `/proc/<pid>/exe` then reads `<path> (deleted)` (proc(5)), which does not resolve,
and so, to a Harper running as root, does a kernel thread, which has no executable link and an
empty argument vector. Another user's process on Linux is "not ours": a sidecar runs as Harper's
user, so a pid that answers `kill(pid, 0)` with `EPERM`, or whose `/proc/<pid>/exe` refuses the
read with `EACCES`, is not one. Its lock is reclaimed, as `main` reclaims a lock whose pid answers
`EPERM`, and a same-user sidecar that is not dumpable, such as a binary with file capabilities, reads
the same way.
`processIdentity.ts` reads no identity outside Linux and darwin, so there a live process answers
"cannot tell". The shutdown stop only reports those. Outside Linux and darwin the reaper falls back
to the spawn-time recorded pid, the one number not read from a file another process may have
rewritten; on Linux and darwin an unidentified sidecar is left running. Windows also keeps the
lock's unconditional restart on a version change, since report-only there would stop sidecar
upgrades.

Started through a component's own `child_process`, with no keeper, a command that runs as another
program reads as "not ours" to its own lock where the platform can identify: a script started
through its shebang runs as its interpreter, and a wrapper that execs a binary runs as that
binary. Each thread after the first to start one takes the lock from the running instance without
a signal and spawns another beside it. That path records no descriptor, so neither the shutdown
stop nor the reaper reads any process it starts, as on `main`. Start the interpreter by path with
`script` declared, the binary itself, or the command through `scope.processes`.

An interpreter is the same binary for every script it runs, so a descriptor whose `command`
is one (`node`, and Harper's own reaper is the first example) must also declare `script`.
Identification then reads the argument vector (`/proc/<pid>/cmdline`, `ps -o args=` on darwin)
and both halves must agree before the answer is `match`; either half reading "not ours" is
decisive, and an argv that cannot be read leaves the whole answer "cannot tell". argv is
process-writable where `/proc/<pid>/exe` is kernel-set. It raises confidence against pid
reuse and stale locks, which is the threat here, and it is not proof against a hostile forger.

## Shutdown and the deaths shutdown never sees

- **Graceful exit** (`harper stop`, SIGTERM): `stopSidecarsAtExit()`
  (`security/processSupervisor/sidecarRegistry.ts`), wired into `bin/run.ts`'s exit listeners,
  SIGTERMs identified sidecars from the main process. Its gate is hdb.pid still naming the
  exiting process: `harper restart` removes that file before its exit, so a handover never
  stops the children its replacement adopts through the version-match lock. Each lock is read,
  decided on and removed inside its gate, with the keeper's record identifying the pid it names,
  so a restart a keeper commits meanwhile is the one stopped. It waits a second at most on a held
  gate, since an exit cannot wait out the lock's deadline. Locks are removed before signalling;
  descriptors stay so the reaper can escalate a SIGTERM-ignoring child. A keeper whose process
  dies of that SIGTERM, or finds its lock gone, ends without a restart.
- **Ungraceful death** (one that runs no JavaScript, such as SIGKILL, so no exit listener): the reaper
  (`security/processSupervisor/sidecarReaper.js`) is a separate OS process run by path and
  never imported, self-contained on node builtins so bare node runs it from the source or built
  tree. On Linux and darwin it runs under a keeper launched outside the node's process group,
  which a signal to that group spares; elsewhere the thread forks it detached. It polls the harper pid; on death it waits a grace window for a `harper restart`
  replacement (leaving the children for adoption), then reads the descriptors at reap time, so
  sidecars recorded after it launched are covered, and SIGTERMs, then SIGKILLs, what it can
  positively identify, reading and removing each lock inside its gate as the shutdown stop does:
  a keeper restarts a crash after the node is gone, so a pid read earlier can be dead by then.
  It is a singleton per node through its own PID lock, named
  `harper-sidecar-reaper`, a name no reaper a component bundles for itself should share: a
  component that still supervises its own sidecars can run a reaper in the same pid directory,
  and aliased singleton locks would leave one reaper's targets unwatched.
  Each boot's first start replaces the previous boot's reaper through the lock's
  identity-checked version mismatch (the version fingerprints the boot's pid). A reaper removes
  its own lock on the way out only while that lock names it and no keeper: a node restarted since
  may have taken the name for a newer reaper, and a keeper releases its own.
- **The reaper's own death** is the one nothing else on the node reports afterwards. Under a keeper
  it is answered as a sidecar's is: the keeper restarts a crash with the backoff whether or not
  the thread that launched it still runs, and its count starts again after `REAPER_STABLE_MS` of
  running, so the cap bounds a crash loop rather than the node's life. Where no keeper runs,
  `#reaperDied` clears `started` and `pid` and sets `error`, which is the field a status surface
  reads, then replaces it on the schedule a sidecar's death already uses: `backoffMs` against
  `RESPAWN_MAX_ATTEMPTS`, on an unref'd timer, which a node inside `process.exit` never runs. An
  owner grades the death by exit status, where a stop signal or a clean code is deliberate and
  anything else, SIGKILL included, is a loss. A joiner has no exit status and relaunches either
  way, which the singleton lock turns into an adoption whenever another thread got there first.
  `#ensureReaper` keys its early return on `started` rather than on presence, or the state a dead
  reaper leaves behind would itself be what prevents the replacement.

## Invariants worth keeping

- One process per `name` per node, no matter the thread count: the PID lock's job. Under a keeper
  the start time identifies it through an exec; started through a component's own `child_process`,
  a command that runs as another program is the exception (The one signalling rule).
- A verdict names the pid it was taken against. Anything that reads `verified` without asking whether the
  process is still the one that was proved will eventually publish a dead process as healthy, which reads
  as a passing health check.
- One respawner per death. Under a keeper that is the keeper, and every thread joins what it
  restarts; `claimDeadPidFileLock` declines while a lock's keeper lives. A thread whose claim another
  took before its keeper committed, or that gave its claim back when its keeper named no pid in time,
  joins what the thread holding the name starts. Without a keeper, the thread that started the child
  restarts it, and reports a stop, a clean exit or a spent budget as not running, as a thread under a
  keeper does. A descriptor's name is one file name, since it names the lock, and never the reaper's
  in any case, since darwin's and Windows' file systems fold case. A thread that only
  joined it is handed a liveness poll and never an exit status, so it cannot tell a crash from a
  deliberate stop; it asks for the death instead, through `claimDeadPidFileLock`
  (security/processSupervisor/pidLockClaim.ts). A joiner restarts only when the lock still names
  the pid that died and it is the thread that renames that lock away, which it decides under the
  gate; a gate held past two seconds leaves the death to its holder. The shutdown stop and the
  reaper remove the lock before they signal, and the version-mismatch restart replaces it inside
  the gate, so by the time a joiner sees a deliberate death the lock no longer names that pid;
  that is the discriminator, and no flag has to be set anywhere.
- The ownerless case is why the claim exists: after an ops-API restart the sidecars survive and
  every thread in the replacement node adopts them, so "the thread that started it" names no one
  and a later death would go unremediated until the next full node restart. Under a keeper the
  keeper survives the restart with them and answers that death itself.
- A keeper's record is read before `exited` is set, and a death with no record whose keeper is
  gone is left alone, since it may have been a stop.
- The claim renames, it does not unlink. `unlinkSync` looks like a test-and-set and is not:
  concurrent unlinks of one name can each report success (measured on darwin at 23 of 300
  eight-thread races, up to three winners). `rename`, `link` and `open(O_EXCL)` were exclusive
  across the same 300; the file primitives that arbitrate here must be one of those.
- The claim decides who tries; the PID lock still decides who spawns. A second thread in the spawn
  for one death reads the first one's claim under the gate and adopts the child it names, so no
  interleaving produces two processes of a command the lock can identify (The one signalling rule).
- No pre-spawn sweep at all. Adjudicating a stale lock and then claiming it were two steps with a window
  between them, and whatever the sweep decided could change before the claim. The gate in
  `pidFileLock.ts` makes the read, the verdict and the write one step to every other thread, so the
  window does not exist to be narrowed.
- No signal without positive identification in the lock, the shutdown stop or the reaper, outside
  the platform fallbacks described under The one signalling rule.
- A stop that is final removes the lock before it signals, since a lock naming a dying process
  makes a reader adopt a corpse. The version-mismatch replacement in `pidFileLock.ts` signals and
  then unlinks; both run inside the gate, so exactly one thread reaches them and no thread deciding
  to adopt reads the lock between the two.
- `harper restart` hands children to the replacement; nothing on the restart path stops them.
- The keeper and the reaper run under bare node from their path and cannot load TypeScript, so each keeps its
  own copy of a rule `pidFileLock.ts`, `processIdentity.ts` or `sidecarRegistry.ts` owns: the lock's parse and
  its gate, identification, the descriptor reader. `conformance.test.js` beside the suite runs each pair over the
  inputs its tables list and fails where the two answer one of them differently; a rule no row reaches can drift
  in either copy without failing it.
