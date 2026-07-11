package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestStage5EndToEnd is the marquee Stage-5 test: the first fully end-to-end run
// against an all-stock C++ Access Point. The pool is a stock condor_master +
// condor_collector + condor_negotiator + condor_schedd (+ the real C++ shadow),
// with OUR pure-Go startd as the pool's only Go daemon (STARTD=<go binary>). A
// stock `condor_submit` of a vanilla+file-transfer job must:
//
//	condor_submit -> C++ schedd queue (Idle)
//	  -> C++ negotiator matches our Go startd's machine ad (Risk 1 surface)
//	  -> C++ schedd MATCH_INFO + REQUEST_CLAIM + ACTIVATE_CLAIM our Go startd
//	  -> the real C++ SHADOW drives our Go starter (first contact of our
//	     syscall/FT client with the C++ shadow: input xfer, exec, output xfer)
//	  -> job runs (slot Claimed/Busy) then completes
//	  -> output files land back in the submit dir
//	  -> condor_history shows JobStatus=4, ExitCode=0
//	  -> our slot returns toward Unclaimed after the queue empties.
//
// It then submits a 2-job cluster to exercise both static slots.
func TestStage5EndToEnd(t *testing.T) {
	for _, tool := range []string{"condor_master", "condor_submit", "condor_q", "condor_history", "condor_config_val", "condor_off"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()

	// Build the Go startd the master launches as the pool's STARTD (pid-tagged
	// basename so pgrep matches exactly this run's process; see stage1).
	binName := fmt.Sprintf("golang-ep-startd-s5-%d", os.Getpid())
	startdBin := filepath.Join(tmp, binName)
	if out, err := exec.Command("go", "build", "-buildvcs=false", "-o", startdBin, "../cmd/startd").CombinedOutput(); err != nil {
		t.Fatalf("building golang-ep startd: %v\n%s", err, out)
	}

	executeDir := filepath.Join(tmp, "execute")
	if err := os.MkdirAll(executeDir, 0o755); err != nil {
		t.Fatalf("mkdir execute: %v", err)
	}

	// Resolve the AUTHORITATIVE platform strings the local C++ pool computes
	// (e.g. macOS 25.x publishes Arch="arm64", OpSys="macOS" -- NOT the Go
	// runtime's "ARM64"/"OSX"). The stock condor_submit default job Requirements
	// is (TARGET.Arch=="<arch>") && (TARGET.OpSys=="<opsys>") && ... &&
	// (TARGET.HasFileTransfer); our slot ad must advertise the exact OpSys string
	// or the negotiator silently no-matches. We inject these into the startd's
	// config so slot.resolvePlatform reads them.
	arch := condorConfigVal(t, "ARCH")
	opsys := condorConfigVal(t, "OPSYS")
	opsysAndVer := condorConfigVal(t, "OPSYSANDVER")
	opsysMajorVer := condorConfigVal(t, "OPSYSMAJORVER")
	t.Logf("authoritative platform: ARCH=%q OPSYS=%q OPSYSANDVER=%q", arch, opsys, opsysAndVer)

	const uidDomain = "golang-ep.test"
	extra := fmt.Sprintf(`
# --- Run golang-ep's startd as the pool's STARTD; everything else is stock C++ ---
STARTD = %s
STARTD_LOG = $(LOG)/StartdLog
STARTD_DEBUG = D_FULLDEBUG
STARTD_ADDRESS_FILE = $(LOG)/.startd_address

# Two static slots over two CPUs so both slots are exercisable.
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

# The authoritative platform strings the C++ schedd/negotiator compute, so our
# Go slot ad's OpSys/Arch match the default job Requirements.
ARCH = %s
OPSYS = %s
OPSYSANDVER = %s
OPSYSMAJORVER = %s

UID_DOMAIN = %s
TRUST_UID_DOMAIN = True

# Negotiate quickly.
NEGOTIATOR_INTERVAL = 5
NEGOTIATOR_MIN_INTERVAL = 1
NEGOTIATOR_CYCLE_DELAY = 1
NEGOTIATOR_DEBUG = D_MATCH

# Exercise the MATCH_INFO=440 surface: the modern negotiator does NOT inform the
# startd of a match by default (the schedd's REQUEST_CLAIM suffices), so we turn
# it on to drive our Matched-state path end to end.
NEGOTIATOR_INFORM_STARTD = True

# Claim sessions require match-password auth + AES (cedar's only cipher).
SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION = TRUE
SEC_DEFAULT_CRYPTO_METHODS = AES
SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = FS
SEC_CLIENT_AUTHENTICATION_METHODS = FS
`, startdBin, arch, opsys, opsysAndVer, opsysMajorVer, uidDomain)

	h := htcondor.SetupCondorHarnessWithConfig(t, extra)
	defer h.Shutdown()
	logDir := h.GetLogDir()
	cfgFile := h.GetConfigFile()

	dumpAllLogs := func() {
		for _, name := range []string{"StartdLog", "SchedLog", "NegotiatorLog", "MatchLog", "ShadowLog", "MasterLog", "CollectorLog"} {
			dumpLog(t, filepath.Join(logDir, name))
		}
		for _, glob := range []string{"ShadowLog*", "StarterLog*"} {
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

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	col := htcondor.NewCollector(h.GetCollectorAddr())

	// The Go startd must advertise both static slots before we submit.
	if slots := waitForSlots(t, ctx, col, 2, 60*time.Second); len(slots) < 2 {
		fail("Go startd never advertised 2 slots (got %d)", len(slots))
	}
	t.Log("Go startd advertised both slots to the C++ collector")

	// ---- (1) Build + submit a vanilla+FT job with the stock condor_submit ----
	const inputContent = "hello-from-cpp-shadow"
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

	// ---- (2) The Go slot must go Claimed/Busy while the job runs ----
	slotName := ""
	if !waitForAnySlot(t, ctx, col, 90*time.Second, func(name string, ad *classad.ClassAd) bool {
		st, _ := ad.EvaluateAttrString("State")
		act, _ := ad.EvaluateAttrString("Activity")
		if st == "Claimed" && act == "Busy" {
			slotName = name
			return true
		}
		return false
	}) {
		fail("no Go slot ever went Claimed/Busy for job %d (negotiator no-match? claim/activate failure?)", cluster)
	}
	t.Logf("Go slot %s is Claimed/Busy running the job (the C++ shadow is driving our starter)", slotName)

	// ---- (3) The job must leave the queue (completed) ----
	if !waitForJobGone(t, cfgFile, cluster, 120*time.Second) {
		fail("job %d.0 never left the queue (never completed)", cluster)
	}
	t.Logf("job %d.0 completed and left the queue", cluster)

	// ---- (4) Output files land back in the submit dir with correct bytes ----
	gotResult, err := os.ReadFile(filepath.Join(iwd, "result.txt"))
	if err != nil {
		fail("explicit output file result.txt not returned: %v", err)
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
	t.Log("output files returned to the submit dir with expected content")

	// ---- (5) condor_history: JobStatus=4 (Completed), ExitCode=0 ----
	if !waitForHistory(t, cfgFile, cluster, 0, 60*time.Second) {
		fail("job %d.0 never showed JobStatus=4 ExitCode=0 in condor_history", cluster)
	}
	t.Logf("job %d.0 in history with JobStatus=4, ExitCode=0", cluster)

	// ---- (6) The slot returns toward Unclaimed after the queue empties ----
	// The C++ schedd releases the claim when it has no more work; CLAIM_WORKLIFE
	// may keep it Claimed/Idle briefly, so we tolerate either terminal state and
	// only require it is no longer Busy.
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
	t.Logf("slot %s settled to %q after the run (Unclaimed or Claimed/Idle per CLAIM_WORKLIFE)", slotName, finalState)

	// ---- (7) A 2-job cluster to exercise both slots (or sequential reuse) ----
	sub2 := filepath.Join(tmp, "job2.sub")
	iwd2 := filepath.Join(tmp, "job2")
	if err := os.MkdirAll(iwd2, 0o755); err != nil {
		t.Fatal(err)
	}
	script2 := "#!/bin/sh\necho \"proc $1 ran\" > out.$1\nexit 0\n"
	script2Path := filepath.Join(iwd2, "job2.sh")
	if err := os.WriteFile(script2Path, []byte(script2), 0o755); err != nil {
		t.Fatal(err)
	}
	sub2Desc := fmt.Sprintf(`universe = vanilla
executable = %s
transfer_executable = true
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
arguments = $(Process)
initialdir = %s
output = job2.$(Process).out
error = job2.$(Process).err
log = job2.log
transfer_output_files = out.$(Process)
request_cpus = 1
request_memory = 128
request_disk = 1024
queue 2
`, script2Path, iwd2)
	if err := os.WriteFile(sub2, []byte(sub2Desc), 0o644); err != nil {
		t.Fatal(err)
	}
	out2 := runCondor(t, cfgFile, 60*time.Second, "condor_submit", sub2)
	cluster2 := parseClusterID(out2)
	if cluster2 <= 0 {
		fail("could not parse cluster id from 2-job submit: %q", out2)
	}
	t.Logf("submitted 2-job cluster %d", cluster2)
	if !waitForJobGone(t, cfgFile, cluster2, 150*time.Second) {
		fail("2-job cluster %d never fully completed", cluster2)
	}
	for proc := 0; proc < 2; proc++ {
		outFile := filepath.Join(iwd2, fmt.Sprintf("out.%d", proc))
		data, err := os.ReadFile(outFile)
		if err != nil {
			fail("2-job cluster: transfer_output_files out.%d not returned: %v", proc, err)
		}
		if want := fmt.Sprintf("proc %d ran\n", proc); string(data) != want {
			fail("out.%d = %q, want %q", proc, string(data), want)
		}
	}
	t.Log("2-job cluster: both procs completed with correct transferred outputs")

	if t.Failed() {
		dumpAllLogs()
	}
	t.Log("Stage 5 OK: stock C++ AP matched, claimed, activated, and ran a vanilla+FT job on the Go startd; outputs correct; both slots exercised")
}

// --- Stage-5 helpers ---

var clusterRe = regexp.MustCompile(`submitted to cluster (\d+)`)

// parseClusterID extracts the cluster id from condor_submit's output.
func parseClusterID(submitOutput string) int {
	m := clusterRe.FindStringSubmatch(submitOutput)
	if len(m) < 2 {
		return -1
	}
	n := 0
	for _, r := range m[1] {
		n = n*10 + int(r-'0')
	}
	return n
}

// condorConfigVal returns the value of a single config macro via
// condor_config_val (the authoritative source for computed platform strings).
func condorConfigVal(t *testing.T, name string) string {
	t.Helper()
	out, err := exec.Command("condor_config_val", name).CombinedOutput()
	if err != nil {
		t.Logf("condor_config_val %s failed: %v (%s)", name, err, out)
		return ""
	}
	return strings.TrimSpace(string(out))
}

// waitForAnySlot polls the collector's Machine ads until pred returns true for
// some slot or the timeout elapses.
func waitForAnySlot(t *testing.T, ctx context.Context, col *htcondor.Collector, timeout time.Duration, pred func(name string, ad *classad.ClassAd) bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for name, ad := range querySlots(ctx, col) {
			if pred(name, ad) {
				return true
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// lastSlotState returns a slot's current "State/Activity" for logging.
func lastSlotState(ctx context.Context, col *htcondor.Collector, slotName string) string {
	ads := querySlots(ctx, col)
	ad, ok := ads[slotName]
	if !ok {
		return "(gone)"
	}
	st, _ := ad.EvaluateAttrString("State")
	act, _ := ad.EvaluateAttrString("Activity")
	return st + "/" + act
}

// waitForJobGone polls condor_q until no job of the cluster remains in the queue.
func waitForJobGone(t *testing.T, cfgFile string, cluster int, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		row := runCondorAllowErr(cfgFile, 20*time.Second, "condor_q", "-allusers", "-af", "ClusterId",
			"-constraint", fmt.Sprintf("ClusterId==%d", cluster))
		if strings.TrimSpace(row) == "" {
			return true
		}
		time.Sleep(1 * time.Second)
	}
	return false
}

// waitForHistory polls condor_history until the job shows JobStatus=4 and
// ExitCode=0.
func waitForHistory(t *testing.T, cfgFile string, cluster, proc int, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		row := runCondorAllowErr(cfgFile, 20*time.Second, "condor_history",
			fmt.Sprintf("%d.%d", cluster, proc), "-af", "JobStatus", "ExitCode")
		f := strings.Fields(strings.TrimSpace(row))
		if len(f) >= 2 && f[0] == "4" && f[1] == "0" {
			return true
		}
		time.Sleep(1 * time.Second)
	}
	return false
}
