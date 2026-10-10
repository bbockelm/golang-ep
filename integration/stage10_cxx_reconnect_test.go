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

// TestStage10CxxShadowReconnect: a stock C++ shadow reconnects to our starter.
// The pool is a stock C++ access point with our Go startd as STARTD, running
// process-mode starters (the mode that survives a lost shadow). While a
// job runs, the schedd is restarted fast (it SIGKILLs its shadows and leaves
// the job running); the new schedd's shadow sends CA_LOCATE_STARTER to our
// startd and CA_RECONNECT_JOB to our starter over the claim session, the user
// log records the reconnect, and the job completes with its output.
func TestStage10CxxShadowReconnect(t *testing.T) {
	for _, tool := range []string{"condor_master", "condor_submit", "condor_q", "condor_history", "condor_config_val", "condor_restart"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()
	startdBin := filepath.Join(tmp, fmt.Sprintf("golang-ep-startd-s10-%d", os.Getpid()))
	if out, err := exec.Command("go", "build", "-buildvcs=false", "-o", startdBin, "../cmd/startd").CombinedOutput(); err != nil {
		t.Fatalf("building golang-ep startd: %v\n%s", err, out)
	}
	starterBin := filepath.Join(tmp, fmt.Sprintf("golang-ep-starter-s10-%d", os.Getpid()))
	buildBin(t, starterBin, "../cmd/starter")
	executeDir := filepath.Join(tmp, "execute")
	if err := os.MkdirAll(executeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Unix socket paths must stay short (sun_path).
	shortBase, err := os.MkdirTemp("/tmp", "ep10")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shortBase) })

	extra := fmt.Sprintf(`
STARTD = %s
STARTD_LOG = $(LOG)/StartdLog
STARTD_DEBUG = D_FULLDEBUG
STARTD_ADDRESS_FILE = $(LOG)/.startd_address
EXECUTE = %s
STARTER_MODE = process
STARTER = %s
EP_STARTER_SOCKET_DIR = %s
EP_CLAIMS_DIR = %s

NUM_CPUS = 1
MEMORY = 512
START = TRUE
SUSPEND = FALSE
PREEMPT = FALSE
WANT_SUSPEND = FALSE
WANT_VACATE = FALSE
UPDATE_INTERVAL = 5
STARTER_UPDATE_INTERVAL = 5

ARCH = %s
OPSYS = %s
OPSYSANDVER = %s
OPSYSMAJORVER = %s

UID_DOMAIN = golang-ep.test
TRUST_UID_DOMAIN = True

NEGOTIATOR_INTERVAL = 5
NEGOTIATOR_MIN_INTERVAL = 1
NEGOTIATOR_CYCLE_DELAY = 1

# Default match-password security; AES is cedar's only cipher.
SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION = TRUE
SEC_DEFAULT_CRYPTO_METHODS = AES
SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = FS
SEC_CLIENT_AUTHENTICATION_METHODS = FS
`, startdBin, executeDir, starterBin, filepath.Join(shortBase, "s"), filepath.Join(shortBase, "c"), condorConfigVal(t, "ARCH"), condorConfigVal(t, "OPSYS"),
		condorConfigVal(t, "OPSYSANDVER"), condorConfigVal(t, "OPSYSMAJORVER"))

	h := htcondor.SetupCondorHarnessWithConfig(t, extra)
	defer h.Shutdown()
	logDir := h.GetLogDir()
	cfgFile := h.GetConfigFile()
	fail := func(format string, args ...any) {
		t.Helper()
		for _, name := range []string{"StartdLog", "SchedLog", "ScheddLog", "MasterLog"} {
			dumpLog(t, filepath.Join(logDir, name))
		}
		matches, _ := filepath.Glob(filepath.Join(logDir, "ShadowLog*"))
		for _, m := range matches {
			dumpLog(t, m)
		}
		t.Fatalf(format, args...)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	col := htcondor.NewCollector(h.GetCollectorAddr())
	if slots := waitForSlots(t, ctx, col, 1, 60*time.Second); len(slots) < 1 {
		fail("Go startd never advertised its slot")
	}

	iwd := filepath.Join(tmp, "job")
	if err := os.MkdirAll(iwd, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nsleep 25\necho reconnected-job-done > result.txt\nexit 0\n"
	scriptPath := filepath.Join(iwd, "job.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	userLog := filepath.Join(iwd, "job.log")
	submitFile := filepath.Join(tmp, "job.sub")
	if err := os.WriteFile(submitFile, []byte(fmt.Sprintf(`universe = vanilla
executable = %s
should_transfer_files = YES
when_to_transfer_output = ON_EXIT
transfer_output_files = result.txt
initialdir = %s
output = job.out
error = job.err
log = %s
request_cpus = 1
request_memory = 128
request_disk = 1024
queue
`, scriptPath, iwd, userLog)), 0o644); err != nil {
		t.Fatal(err)
	}
	cluster := parseClusterID(runCondor(t, cfgFile, 60*time.Second, "condor_submit", submitFile))
	if cluster <= 0 {
		fail("could not parse cluster id")
	}

	if !waitForAnySlot(t, ctx, col, 90*time.Second, func(_ string, ad *classad.ClassAd) bool {
		act, _ := ad.EvaluateAttrString("Activity")
		return act == "Busy"
	}) {
		fail("slot never went Busy for job %d", cluster)
	}
	if !waitForLogContains(userLog, "Job executing on host", 60*time.Second) {
		fail("job %d never logged an execute event", cluster)
	}

	// Kill the shadow with the schedd; the job keeps running on our starter.
	out := runCondorAllowErr(cfgFile, 60*time.Second, "condor_restart", "-fast", "-daemon", "schedd")
	t.Logf("condor_restart -fast -daemon schedd:\n%s", out)

	if !waitForLogContains(userLog, "Job reconnected to", 120*time.Second) {
		fail("the C++ shadow never reconnected to the starter (no reconnect event in the user log)")
	}
	if data, _ := os.ReadFile(userLog); strings.Contains(string(data), "Job reconnection failed") {
		fail("user log records a failed reconnect:\n%s", data)
	}
	t.Log("C++ shadow reconnected to the Go starter")

	if !waitForJobGone(t, cfgFile, cluster, 120*time.Second) {
		fail("job %d never completed after the reconnect", cluster)
	}
	got, err := os.ReadFile(filepath.Join(iwd, "result.txt"))
	if err != nil || string(got) != "reconnected-job-done\n" {
		fail("result.txt = %q, %v; want the job's output after reconnect", got, err)
	}
	if !waitForHistory(t, cfgFile, cluster, 0, 60*time.Second) {
		fail("job %d never showed JobStatus=4 ExitCode=0 in condor_history", cluster)
	}
}
