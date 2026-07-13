# golang-ep

A pure-Go HTCondor **Execution Point** — a `condor_startd` and `condor_starter`
reimplemented in Go. It advertises slots to a collector, is matched and claimed
like any HTCondor EP, and runs **vanilla-universe jobs with file transfer**. It
interoperates with a stock C++ HTCondor pool (or the all-Go
[golang-ap](https://github.com/bbockelm/golang-ap) /
[golang-collector](https://github.com/bbockelm/golang-collector) daemons): the
Go startd runs as your `STARTD`, under a normal `condor_master`, and a stock
`condor_schedd`/`condor_negotiator`/`condor_collector` can drive it.

> Maturity: works end-to-end (vanilla + file transfer, static and partitionable
> slots, matched/claimed by C++ or Go daemons), but it is an MVP — see
> [Scope and limitations](#scope-and-limitations). Not yet a hardened,
> drop-in production replacement for the C++ `condor_startd`.

## What you get

- A `condor_startd` that detects the host's CPUs/memory/disk, advertises
  **static or partitionable slots** to the collector, and is matched by the
  negotiator and claimed by a schedd exactly like a C++ EP.
- Runs **vanilla-universe jobs** with **file transfer** (input/output sandbox),
  reporting exit status, CPU, and memory back to the shadow.
- Standard claim lifecycle: `REQUEST_CLAIM` / `ACTIVATE_CLAIM` / `ALIVE` lease /
  `DEACTIVATE_CLAIM` (soft-vacate → hard-kill escalation) / `RELEASE_CLAIM`.
- Optional **restart-survivable starters** (see below): jobs keep running across
  a startd restart.

## Requirements

- **A C++ HTCondor install** for the process supervisor (`condor_master`) and
  the rest of the pool (collector, negotiator, schedd/shadow) — or the pure-Go
  equivalents. Tested against recent HTCondor (24.x–25.x). The Go startd is a
  daemon in your `DAEMON_LIST`; it does not replace the master.
- **`USE_SHARED_PORT = True`** — the Go daemon adopts the master's inherited
  shared-port socket.
- **`SEC_DEFAULT_CRYPTO_METHODS = AES`** — the Go security stack implements
  AES-GCM only.
- Linux or macOS.

## Install

golang-ep builds against released module versions — no special checkout needed:

```sh
git clone https://github.com/bbockelm/golang-ep
cd golang-ep
go build -o condor_startd  ./cmd/startd     # the daemon (runs under condor_master)
go build -o condor_starter ./cmd/starter    # the per-job starter (process mode only)
```

Install the two binaries somewhere on the machine (e.g. `/opt/golang-ep/bin`)
and point the config at them (below). The `condor_starter` binary is only used
when `STARTER_MODE = process`; the default goroutine mode needs just the startd.

## Configure

Run the Go startd as the `STARTD` in an otherwise normal HTCondor config. A
minimal drop-in (`/etc/condor/config.d/50-golang-ep.conf`):

```
USE_SHARED_PORT = True
SEC_DEFAULT_CRYPTO_METHODS = AES

# Run the Go startd instead of the C++ one.
DAEMON_LIST = $(DAEMON_LIST) STARTD
STARTD = /opt/golang-ep/bin/condor_startd

# Slots and resources
NUM_CPUS = 8                 # override detected CPUs (optional)
MEMORY   = 16000             # override detected memory, MB (optional)
EXECUTE  = /var/lib/condor/execute
NUM_SLOTS = 1                # number of static slots (default 1)
START = TRUE                 # START expression

# Partitionable slot (carves dynamic slots on demand) instead of static:
# SLOT_TYPE_1_PARTITIONABLE = True
```

Key config knobs (all optional unless noted; HTCondor names are honored):

| Knob | Default | Meaning |
|------|---------|---------|
| `EXECUTE` | system temp dir | Directory job sandboxes are created under (set this in production) |
| `NUM_CPUS` / `MEMORY` | detected | Override advertised Cpus / Memory (MB) |
| `NUM_SLOTS` | `1` | Number of static slots to carve |
| `SLOT_TYPE_1_PARTITIONABLE` (or `EP_PARTITIONABLE_SLOT`) | `False` | Advertise one partitionable slot; dynamic slots are carved per claim |
| `START` | `TRUE` | START expression the slot advertises |
| `UPDATE_INTERVAL` | `300` | Seconds between collector updates |
| `UID_DOMAIN` / `FILESYSTEM_DOMAIN` | hostname | Advertised domains |
| `MAX_CLAIM_ALIVES_MISSED` | `6` | Missed ALIVEs before a claim lease expires |
| `KILLING_TIMEOUT` | `30` | Seconds a soft vacate waits before hard-kill |
| `STARTER_MODE` | `goroutine` | `goroutine` (in-process) or `process` (separate `condor_starter`) |
| `STARTER` | — | Path to the `condor_starter` binary; **required** when `STARTER_MODE = process` |
| `EP_CLAIMS_DIR` | `$(SPOOL)/ep/claims` | Durable claim store (process mode) |
| `EP_STARTER_SOCKET_DIR` | `$(SPOOL)/ep/starters` | Per-claim starter sockets (process mode) |

## Run and verify

Start (or restart) the pool as usual and confirm the Go startd is advertising:

```sh
condor_reconfig      # or: condor_restart / systemctl restart condor
condor_status        # your slots should appear, State=Unclaimed
```

Submit a vanilla job with file transfer and watch it run on the Go EP:

```
# job.sub
executable            = /bin/sh
arguments             = "-c 'echo hello > out.txt'"
should_transfer_files = YES
transfer_output_files = out.txt
output = job.out
error  = job.err
log    = job.log
queue
```

```sh
condor_submit job.sub
condor_q         # Idle → Running → gone
condor_history   # completed, ExitCode 0; out.txt lands back in the submit dir
```

## Restart-survivable starters (optional)

Set `STARTER_MODE = process` (and `STARTER = <path to condor_starter>`) to run
each job's starter as a **separate process** connected to the startd over a Unix
socket, with the shadow's syscall connection handed across via `SCM_RIGHTS`.

The startd persists claim state to `EP_CLAIMS_DIR`, so **a startd restart does
not kill running jobs**: the surviving starter keeps the job running, and the
restarted startd re-adopts it and resumes the claim lease. (The C++ startd, by
contrast, wipes execute directories and orphans starters on restart.) This is
the foundation for decoupling starters from the startd lifecycle — e.g. running
them in their own systemd slices.

## Scope and limitations

- **Vanilla universe only.** No docker/container/VM/parallel/local/scheduler
  universes.
- **Same-user execution.** Jobs run as the user the startd runs as; there is no
  per-job UID switching / privilege separation yet.
- **No cgroup/systemd resource enforcement.** Job control is process-group +
  `waitpid` with `rusage` sampling; there is no memory/CPU cgroup limiting.
- **MVP hardening.** Suspend/continue is plumbed but lightly exercised; some
  policy knobs (e.g. `RANK`, preemption/retirement) are minimal.

## Related

- [golang-ap](https://github.com/bbockelm/golang-ap) — pure-Go schedd + shadow (the Access Point)
- [golang-collector](https://github.com/bbockelm/golang-collector) — pure-Go collector + negotiator
- [golang-htcondor](https://github.com/bbockelm/golang-htcondor) — Go HTCondor client library
- [cedar](https://github.com/bbockelm/cedar) — the CEDAR wire protocol + security in Go
