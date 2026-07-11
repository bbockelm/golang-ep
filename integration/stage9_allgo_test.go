package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestStage9AllGo is the marquee Stage-9 test: the maximally-Go HTCondor
// pipeline. Every daemon that matters for scheduling and running a job is our
// Go code; only condor_master (the process supervisor) stays C++:
//
//	COLLECTOR  = golang-collector        (Go)
//	NEGOTIATOR = golang-negotiator       (Go)
//	SCHEDD     = golang-ap schedd         (Go; in-process shadow drives our starter)
//	STARTD     = golang-ep startd         (Go; this repo)
//	STARTER    = golang-ep starter        (Go; goroutine mode, in-process to the startd)
//	MASTER     = condor_master            (C++ — supervisor only, as in every prior stage)
//
// A stock condor_submit of a vanilla+file-transfer job must drive the whole
// all-Go path:
//
//	condor_submit -> Go schedd queue (Idle)
//	  -> Go collector sees the Submitter + Machine ads (incl. startd-private claim ids)
//	  -> Go negotiator queries the Go collector, spins the pie, NEGOTIATEs with the Go schedd
//	  -> Go schedd REQUEST_CLAIM + ACTIVATE_CLAIM our Go startd (first Go-schedd <-> Go-startd contact)
//	  -> Go schedd's in-process shadow drives our Go starter (syscalls + input/output file transfer)
//	  -> our startd sends ALIVE to the Go schedd; job runs (slot Claimed/Busy)
//	  -> job completes; output files land back in the submit dir; job leaves the queue.
//
// This is the mirror-image of Stage 5 (which used a fully stock C++ AP): here the
// AP itself is Go, so the schedd<->startd claim/activate wire and the
// shadow<->starter syscall/FT wire are both exercised entirely between our own
// Go daemons for the first time.
func TestStage9AllGo(t *testing.T) {
	for _, tool := range []string{"condor_master", "condor_submit", "condor_q", "condor_config_val"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()

	// Build all four Go daemons the master will launch. Pid-tagged basenames so
	// pgrep/cleanup match exactly this run's processes and never a leaked peer.
	pid := os.Getpid()
	startdBin := buildGoDaemon(t, tmp, ".", "../cmd/startd", fmt.Sprintf("golang-ep-startd-s9-%d", pid))
	scheddBin := buildGoDaemon(t, tmp, "/Users/bbockelm/projects/golang-ap", "./cmd/schedd", fmt.Sprintf("golang-ap-schedd-s9-%d", pid))
	collectorBin := buildGoDaemon(t, tmp, "/Users/bbockelm/projects/golang-collector", "./cmd/golang-collector", fmt.Sprintf("golang-collector-s9-%d", pid))
	negotiatorBin := buildGoDaemon(t, tmp, "/Users/bbockelm/projects/golang-collector", "./cmd/golang-negotiator", fmt.Sprintf("golang-negotiator-s9-%d", pid))

	executeDir := filepath.Join(tmp, "execute")
	if err := os.MkdirAll(executeDir, 0o755); err != nil {
		t.Fatalf("mkdir execute: %v", err)
	}

	// The Go startd's slot ad must carry the authoritative platform strings the
	// Go negotiator matches the default job Requirements against (macOS 25.x
	// publishes Arch="arm64", OpSys="macOS" — NOT the Go runtime's "ARM64"/"OSX").
	arch := condorConfigVal(t, "ARCH")
	opsys := condorConfigVal(t, "OPSYS")
	opsysAndVer := condorConfigVal(t, "OPSYSANDVER")
	opsysMajorVer := condorConfigVal(t, "OPSYSMAJORVER")
	t.Logf("authoritative platform: ARCH=%q OPSYS=%q OPSYSANDVER=%q", arch, opsys, opsysAndVer)

	const uidDomain = "golang-ep.test"
	extra := fmt.Sprintf(`
# ===================================================================
# Stage 9: the all-Go pipeline. Master stays C++; everything else Go.
# ===================================================================

# --- COLLECTOR = golang-collector -------------------------------------------
COLLECTOR = %s
COLLECTOR_LOG = $(LOG)/CollectorLog
COLLECTOR_ADDRESS_FILE = $(LOG)/.collector_address
COLLECTOR_DEBUG = D_FULLDEBUG
# No CONDOR_VIEW_HOST forwarding in the Go collector; the harness points it at
# the collector itself, so disable it to avoid meaningless forward attempts.
CONDOR_VIEW_HOST =

# --- NEGOTIATOR = golang-negotiator -----------------------------------------
NEGOTIATOR = %s
NEGOTIATOR_LOG = $(LOG)/NegotiatorLog
NEGOTIATOR_ADDRESS_FILE = $(LOG)/.negotiator_address
NEGOTIATOR_DEBUG = D_FULLDEBUG
NEGOTIATOR_INTERVAL = 5
NEGOTIATOR_MIN_INTERVAL = 1
NEGOTIATOR_CYCLE_DELAY = 1
NEGOTIATOR_UPDATE_INTERVAL = 5

# --- SCHEDD = golang-ap schedd ----------------------------------------------
SCHEDD = %s
SCHEDD_LOG = $(LOG)/ScheddLog
SCHEDD_DEBUG = D_FULLDEBUG
SCHEDD_INTERVAL = 5
SCHEDD_ADDRESS_FILE = $(LOG)/.schedd_address

# --- STARTD = golang-ep startd (this repo) ----------------------------------
STARTD = %s
STARTD_LOG = $(LOG)/StartdLog
STARTD_DEBUG = D_FULLDEBUG
STARTD_ADDRESS_FILE = $(LOG)/.startd_address

# Two static slots over two CPUs so both slots are exercisable (p-slots in an
# all-Go pipeline have extra requirements — kept out of the Stage 9 happy path).
NUM_CPUS = 2
MEMORY = 512
NUM_SLOTS = 2
START = TRUE
SUSPEND = FALSE
PREEMPT = FALSE
WANT_SUSPEND = FALSE
WANT_VACATE = FALSE
UPDATE_INTERVAL = 5
STARTER_UPDATE_INTERVAL = 5

# Authoritative platform strings so our Go slot ad's OpSys/Arch match the
# default job Requirements the Go negotiator evaluates.
ARCH = %s
OPSYS = %s
OPSYSANDVER = %s
OPSYSMAJORVER = %s

UID_DOMAIN = %s
TRUST_UID_DOMAIN = True

# Claim sessions require match-password auth + AES (cedar's only cipher).
SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION = TRUE
SEC_DEFAULT_CRYPTO_METHODS = AES
SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = FS
SEC_CLIENT_AUTHENTICATION_METHODS = FS
`, collectorBin, negotiatorBin, scheddBin, startdBin,
		arch, opsys, opsysAndVer, opsysMajorVer, uidDomain)

	h := htcondor.SetupCondorHarnessWithConfig(t, extra)
	defer h.Shutdown()
	logDir := h.GetLogDir()
	cfgFile := h.GetConfigFile()

	dumpAllLogs := func() {
		for _, name := range []string{"CollectorLog", "NegotiatorLog", "ScheddLog", "StartdLog", "MasterLog"} {
			dumpLog(t, filepath.Join(logDir, name))
		}
		for _, glob := range []string{"StarterLog*", "ShadowLog*"} {
			matches, _ := filepath.Glob(filepath.Join(logDir, glob))
			for _, m := range matches {
				dumpLog(t, m)
			}
		}
	}
	fail := func(format string, args ...any) {
		t.Helper()
		dumpAllLogs()
		t.Fatalf(format, args...)
	}

	// The Go schedd must publish its address before condor_submit can reach it.
	if !waitForFileS9(filepath.Join(logDir, ".schedd_address"), 60*time.Second) {
		fail("Go schedd never wrote its address file")
	}
	t.Log("Go schedd published its address")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	col := htcondor.NewCollector(h.GetCollectorAddr())

	// The Go startd must advertise both static slots to the Go collector.
	if slots := waitForSlots(t, ctx, col, 2, 90*time.Second); len(slots) < 2 {
		fail("Go startd never advertised 2 slots to the Go collector (got %d)", len(slots))
	}
	t.Log("Go startd advertised both slots to the Go collector")

	// ---- (1) Build + submit a vanilla+FT job with the stock condor_submit ----
	const inputContent = "hello-from-all-go-pipeline"
	iwd := filepath.Join(tmp, "job")
	if err := os.MkdirAll(iwd, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n" +
		"expected='" + inputContent + "'\n" +
		"got=$(cat input.dat)\n" +
		"if [ \"$got\" != \"$expected\" ]; then\n" +
		"  echo \"MISMATCH: got [$got] want [$expected]\" 1>&2\n" +
		"  exit 17\n" +
		"fi\n" +
		"echo \"job stdout ok: $got\"\n" +
		"printf 'RESULT:%s\\n' \"$got\" > result.txt\n" +
		"sleep 5\n" +
		"exit 0\n"
	scriptPath := filepath.Join(iwd, "job.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	if err := os.WriteFile(filepath.Join(iwd, "input.dat"), []byte(inputContent), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	submitFile := filepath.Join(tmp, "job.sub")
	subDesc := fmt.Sprintf(`universe = vanilla
executable = %s
transfer_executable = true
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
transfer_input_files = %s
initialdir = %s
output = job.out
error = job.err
log = job.log
transfer_output_files = result.txt
request_cpus = 1
request_memory = 128
request_disk = 1024
queue
`, scriptPath, filepath.Join(iwd, "input.dat"), iwd)
	if err := os.WriteFile(submitFile, []byte(subDesc), 0o644); err != nil {
		t.Fatal(err)
	}

	out := runCondor(t, cfgFile, 60*time.Second, "condor_submit", submitFile)
	t.Logf("condor_submit:\n%s", out)
	cluster := parseClusterID(out)
	if cluster <= 0 {
		fail("could not parse cluster id from condor_submit output: %q", out)
	}

	// ---- (2) The Go slot must go Claimed/Busy: the Go schedd claimed + activated
	//          our Go startd, and its in-process shadow is driving our starter. ----
	slotName := ""
	if !waitForAnySlot(t, ctx, col, 120*time.Second, func(name string, ad *classad.ClassAd) bool {
		st, _ := ad.EvaluateAttrString("State")
		act, _ := ad.EvaluateAttrString("Activity")
		if st == "Claimed" && act == "Busy" {
			slotName = name
			return true
		}
		return false
	}) {
		fail("no Go slot ever went Claimed/Busy for job %d (Go negotiator no-match? Go schedd<->Go startd claim/activate failure?)", cluster)
	}
	t.Logf("Go slot %s is Claimed/Busy: the Go schedd claimed+activated the Go startd; its shadow drives our starter", slotName)

	// ---- (3) The job must leave the queue (completed) ----
	if !waitForJobGone(t, cfgFile, cluster, 120*time.Second) {
		fail("job %d.0 never left the Go schedd's queue (never completed)", cluster)
	}
	t.Logf("job %d.0 completed and left the queue", cluster)

	// ---- (4) Output files land back in the submit dir with correct bytes ----
	gotResult, err := os.ReadFile(filepath.Join(iwd, "result.txt"))
	if err != nil {
		fail("transfer_output_files result.txt not returned by the Go shadow: %v", err)
	}
	if want := "RESULT:" + inputContent + "\n"; string(gotResult) != want {
		fail("result.txt = %q, want %q", string(gotResult), want)
	}
	gotStdout, err := os.ReadFile(filepath.Join(iwd, "job.out"))
	if err != nil {
		fail("captured stdout job.out not returned: %v", err)
	}
	if want := "job stdout ok: " + inputContent; !strings.Contains(string(gotStdout), want) {
		fail("job.out = %q, want it to contain %q", string(gotStdout), want)
	}
	t.Log("output files returned to the submit dir with expected content (Go shadow -> Go starter output transfer)")

	// ---- (5) The slot returns off Busy after the job finishes ----
	if !waitForCollectorSlot(t, ctx, col, slotName, 90*time.Second, func(ad *classad.ClassAd) string {
		act, _ := ad.EvaluateAttrString("Activity")
		st, _ := ad.EvaluateAttrString("State")
		if act == "Busy" {
			return fmt.Sprintf("State=%s Activity=%s (still Busy)", st, act)
		}
		return ""
	}) {
		fail("slot %s never left Claimed/Busy after the job finished", slotName)
	}
	finalState := lastSlotState(ctx, col, slotName)
	t.Logf("slot %s settled to %q after the run", slotName, finalState)

	if t.Failed() {
		dumpAllLogs()
	}
	t.Log("Stage 9 OK: an all-Go pipeline (Go collector + negotiator + schedd + startd + starter) " +
		"matched, claimed, activated, and ran a vanilla+FT job with file transfer end to end; outputs correct")
}

// buildGoDaemon builds a Go binary from moduleDir/pkg to tmp/name and returns its
// path. moduleDir is the sibling module's root ("." for golang-ep itself); pkg is
// the package path relative to that module (e.g. "./cmd/schedd").
func buildGoDaemon(t *testing.T, tmp, moduleDir, pkg, name string) string {
	t.Helper()
	outPath := filepath.Join(tmp, name)
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", outPath, pkg)
	cmd.Dir = moduleDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building %s (%s in %s): %v\n%s", name, pkg, moduleDir, err, out)
	}
	return outPath
}

// waitForFileS9 polls until path exists or the timeout elapses.
func waitForFileS9(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}
