# golang-ep

A pure-Go HTCondor **Execution Point** — a `condor_startd` and `condor_starter`
reimplemented in Go — that a stock C++ HTCondor Access Point can match, claim,
and run vanilla-universe jobs on, with file transfer. It is the execute-side
counterpart to [golang-ap](https://github.com/bbockelm/golang-ap) (the pure-Go
schedd + shadow).

> Status: research / MVP. It runs real jobs end-to-end against both a fully
> stock C++ pool and an all-Go pipeline, but it is not a drop-in replacement
> for a production `condor_startd`.

## Why it exists

Beyond proving that the EP side of HTCondor can be built in Go, this repo
explores one deliberate departure from the C++ implementation:

**The starter is not necessarily a child of the startd.** The startd↔starter
contract is abstracted so a starter can run either as an in-process goroutine
or as a **separate process** that talks to the startd over a Unix domain
socket. Because the shadow's syscall connection lives in the starter process
(handed over via `SCM_RIGHTS` plus a byte-exact transfer of the live AES-GCM
stream state), **a startd restart does not kill running jobs**: the surviving
starter keeps the job running, and the restarted startd re-adopts it from
on-disk claim state. The C++ startd has no such path — it wipes execute
directories on restart. This is the groundwork for running starters in
dynamically-allocated systemd slices, decoupled from the startd lifecycle.

## What works

The functionality was built and verified as a nine-stage ladder, each exiting
via an integration test under a real (mixed Go/C++) personal condor:

| Area | Detail |
|------|--------|
| Advertising | Machine/slot ads (public + private, with `ClaimId`) to the collector |
| Claiming | Match-password claim-id minting, `REQUEST_CLAIM`/`RELEASE_CLAIM`, startd→schedd `ALIVE` lease |
| Activation | `ACTIVATE_CLAIM` with syscall-socket takeover; remote-syscall client vs. the shadow |
| File transfer | Starter as the file-transfer client (input download, output upload) |
| Stock-AP E2E | A job submitted through a **fully stock C++ AP** runs to completion |
| Process starter | Separate-process starter with the encrypted syscall-socket handoff |
| Restart survival | `kill -9` the startd mid-job → starter survives → restarted startd re-adopts → job completes; plus `CA_LOCATE_STARTER`/`CA_RECONNECT_JOB` shadow-driven reconnect |
| Partitionable slots | Dynamic-slot carving, leftovers replies, resource subtraction, `ChildClaimIds` |
| Vacate/preempt | `DEACTIVATE_CLAIM` 403/404/413 with soft→hard escalation; suspend/continue |
| All-Go pipeline | Go collector + negotiator + schedd + startd + starter (only `condor_master` is C++) |

Only three wire boundaries require C++ compatibility — startd↔collector/
negotiator, startd↔schedd (claiming/ALIVE), and starter↔shadow (remote
syscalls, file transfer, `CA_RECONNECT_JOB`). The startd↔starter contract is
entirely internal to this project.

## Layout

```
cmd/startd/          daemon bootstrap (runs under condor_master)
cmd/starter/         process-mode starter executable
internal/startd/     single-writer event loop, command handlers, re-adoption
internal/slot/       resource detection, machine/slot ads, partitionable slots
internal/claim/      claim state machine + minting
internal/starter/    job exec/monitor, file-transfer client, transports (goroutine + Unix socket)
internal/persist/    collections-backed durable claim store
internal/reconnect/  CA_LOCATE_STARTER (startd) + CA_RECONNECT_JOB (starter)
internal/advertise/  machine-ad advertising loop
internal/adwire/     ClassAd wire codec for private ("ZKM") attributes
integration/         stage1..9 regression ladder
```

## Building and testing

golang-ep depends on **unreleased** changes in sibling repositories
([cedar](https://github.com/bbockelm/cedar),
[golang-htcondor](https://github.com/bbockelm/golang-htcondor),
[golang-ap](https://github.com/bbockelm/golang-ap), and
[classad](https://github.com/PelicanPlatform/classad)), wired in via `replace`
directives in [`go.mod`](go.mod). Check those repos out alongside this one and
adjust the `replace` paths to match your layout (they default to the
developer's workspace).

```sh
# Unit tests (no external services required):
go test ./internal/... -race

# The integration ladder additionally requires a built HTCondor
# (condor_master, condor_submit, ...) on PATH and the sibling Go repos.
# It is slow and is not run in CI; run individual stages locally:
go test ./integration -run Stage5 -v
```

Requires the `USE_SHARED_PORT=True` and `SEC_DEFAULT_CRYPTO_METHODS=AES`
configuration that the Go daemon/cedar stack assumes.

## Related

- [golang-ap](https://github.com/bbockelm/golang-ap) — pure-Go schedd + shadow (the Access Point)
- [golang-collector](https://github.com/bbockelm/golang-collector) — pure-Go collector + negotiator
- [golang-htcondor](https://github.com/bbockelm/golang-htcondor) — Go HTCondor client library
- [cedar](https://github.com/bbockelm/cedar) — the CEDAR wire protocol + security in Go
