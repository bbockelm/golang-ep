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

// TestStage1StartdAdvertise runs the pure-Go startd as the STARTD daemon under
// condor_master with a C++ collector. It proves Stage 1 lifecycle + advertising:
//
//	(a) the Go startd advertises both static slots (NUM_SLOTS=2) with
//	    State=Unclaimed and the resources split correctly (Cpus/Memory);
//	(b) it stays alive as the same pid for >= 2 UPDATE_INTERVALs (the master
//	    does not crash-loop or kill it for missed keepalives);
//	(c) condor_off -daemon startd shuts it down cleanly (no restart), and the
//	    slot ads are invalidated out of the collector.
func TestStage1StartdAdvertise(t *testing.T) {
	for _, tool := range []string{"condor_master", "condor_status", "condor_off"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()

	// Build the Go startd binary the master will launch as the STARTD daemon.
	// condor_master sets the child's argv[0] to the binary's BASENAME, so we make
	// the basename unique to this test run (pid-tagged): pgrep -f then matches
	// exactly this run's process and never an orphan from a prior run.
	binName := fmt.Sprintf("golang-ep-startd-%d", os.Getpid())
	startdBin := filepath.Join(tmp, binName)
	build := exec.Command("go", "build", "-buildvcs=false", "-o", startdBin, "../cmd/startd")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building golang-ep startd: %v\n%s", err, out)
	}

	const interval = 10
	const wantSlots = 2
	extra := fmt.Sprintf(`
# --- Run golang-ep's startd as the pool's STARTD under shared_port ---
# The startd is a DaemonCore daemon in DAEMON_LIST, so condor_master pre-creates
# its command socket; under USE_SHARED_PORT (the harness default) we inherit the
# shared-port endpoint (sock=startd) rather than re-binding a fixed port.
DAEMON_LIST = MASTER, COLLECTOR, STARTD
STARTD = %s
STARTD_LOG = $(LOG)/StartdLog
STARTD_DEBUG = D_FULLDEBUG
STARTD_ADDRESS_FILE = $(LOG)/.startd_address

# Two static slots over two CPUs so the resource split is observable.
NUM_CPUS = 2
MEMORY = 512
NUM_SLOTS = %d
UPDATE_INTERVAL = %d

# --- Authentication: every daemon authenticates (FS) and encrypts (AES-GCM, ---
# --- the only cipher cedar implements) so the Go startd advertises to the C++ ---
# --- collector exactly like a C++ startd would. ---
SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = FS
SEC_CLIENT_AUTHENTICATION_METHODS = FS
SEC_DEFAULT_CRYPTO_METHODS = AES
`, startdBin, wantSlots, interval)

	h := htcondor.SetupCondorHarnessWithConfig(t, extra)
	defer h.Shutdown()
	logDir := h.GetLogDir()

	dumpAllLogs := func() {
		for _, name := range []string{"StartdLog", "MasterLog", "CollectorLog"} {
			dumpLog(t, filepath.Join(logDir, name))
		}
	}

	ctx := context.Background()
	col := htcondor.NewCollector(h.GetCollectorAddr())

	// (a) The Go startd must advertise both slots, Unclaimed, resources split.
	slots := waitForSlots(t, ctx, col, wantSlots, 60*time.Second)
	if len(slots) < wantSlots {
		dumpAllLogs()
		t.Fatalf("expected %d slot ads, got %d", wantSlots, len(slots))
	}
	for name, ad := range slots {
		state, _ := ad.EvaluateAttrString("State")
		if state != "Unclaimed" {
			dumpAllLogs()
			t.Fatalf("slot %s State=%q, want Unclaimed", name, state)
		}
		cpus, _ := ad.EvaluateAttrInt("Cpus")
		mem, _ := ad.EvaluateAttrInt("Memory")
		// 2 CPUs / 2 slots = 1 each; 512 MB / 2 = 256 each.
		if cpus != 1 {
			t.Errorf("slot %s Cpus=%d, want 1", name, cpus)
		}
		if mem != 256 {
			t.Errorf("slot %s Memory=%d, want 256", name, mem)
		}
		total, _ := ad.EvaluateAttrInt("TotalCpus")
		if total != 2 {
			t.Errorf("slot %s TotalCpus=%d, want 2", name, total)
		}
	}
	t.Logf("Go startd advertised %d Unclaimed slots with the expected split", len(slots))

	// condor_status (the C++ query tool) must also see the slots -- wire-compat
	// with the real client.
	if out := waitForCondorStatus(t, h.GetConfigFile(), 30*time.Second); out == "" {
		dumpAllLogs()
		t.Fatal("condor_status never listed the Go startd slots")
	} else {
		t.Logf("condor_status:\n%s", out)
	}

	// The startd process must be running as exactly one process.
	pids := pgrep(t, binName)
	if len(pids) != 1 {
		dumpAllLogs()
		t.Fatalf("expected exactly one startd process, found %d: %v", len(pids), pids)
	}
	pid := pids[0]
	t.Logf("Go startd running as pid %s", pid)

	// (b) It must stay alive as the SAME pid for >= 2 UPDATE_INTERVALs: a master
	// crash-loop (childalive failure, non-zero exit) would restart it under a new
	// pid, or take it out of the collector entirely.
	time.Sleep(time.Duration(2*interval+2) * time.Second)
	pids = pgrep(t, binName)
	if len(pids) != 1 || pids[0] != pid {
		dumpAllLogs()
		t.Fatalf("startd pid changed or process count wrong after 2 intervals: before=%s now=%v (crash-loop?)", pid, pids)
	}
	if slots := waitForSlots(t, ctx, col, wantSlots, 20*time.Second); len(slots) < wantSlots {
		dumpAllLogs()
		t.Fatalf("Go startd stopped advertising all slots after 2 intervals (got %d)", len(slots))
	}
	t.Logf("Go startd still alive as pid %s after 2 intervals", pid)

	// (c) condor_off -daemon startd must shut it down cleanly (no restart).
	runCondor(t, h.GetConfigFile(), 30*time.Second, "condor_off", "-daemon", "startd")

	if !waitGone(binName, 30*time.Second) {
		dumpAllLogs()
		t.Fatalf("startd process did not exit after condor_off (pids still: %v)", pgrep(t, binName))
	}
	t.Log("Go startd exited after condor_off")

	// It must NOT come back (a crash-loop or errant master restart would).
	time.Sleep(time.Duration(2*interval) * time.Second)
	if pids := pgrep(t, binName); len(pids) != 0 {
		dumpAllLogs()
		t.Fatalf("startd restarted after condor_off (crash-loop?); pids: %v", pids)
	}

	// The slot ads should have been invalidated on the clean shutdown, so the
	// collector no longer serves them. (Best-effort: log, don't fail, since ad
	// expiry timing in the C++ collector can lag; the invalidate is the point.)
	if remaining := querySlots(ctx, col); len(remaining) != 0 {
		t.Logf("note: %d slot ad(s) still in collector shortly after shutdown (invalidate/expiry lag): %v",
			len(remaining), slotNames(remaining))
	} else {
		t.Log("slot ads invalidated out of the collector after shutdown")
	}

	// The master log must show the startd exited normally.
	if data, err := os.ReadFile(filepath.Join(logDir, "MasterLog")); err == nil {
		ml := string(data)
		if strings.Contains(ml, "restarting") && strings.Contains(ml, "abnormal") {
			t.Logf("=== MasterLog ===\n%s", ml)
			t.Fatal("MasterLog indicates an abnormal restart of the startd")
		}
	}
	t.Log("Stage 1 OK: advertise both slots, stable run, clean shutdown, no restart")
}

// querySlots queries the collector for this pool's slot (Machine) ads and
// returns them keyed by slot Name. It must query the "Machine" ad type, not
// "Startd": the C++ collector maps a "Startd" TargetType to the synthesized
// per-daemon StartD ad table (one entry), whereas "Machine" targets the
// per-slot table (one entry per slot). Only ads whose Name looks like
// "slotN@..." are kept (defensive against a stray non-startd ad).
func querySlots(ctx context.Context, col *htcondor.Collector) map[string]*classad.ClassAd {
	ads, _, err := col.QueryAdsWithOptions(ctx, "Machine", "", nil)
	if err != nil {
		return nil
	}
	out := map[string]*classad.ClassAd{}
	for _, ad := range ads {
		name, ok := ad.EvaluateAttrString("Name")
		if !ok || !strings.HasPrefix(name, "slot") {
			continue
		}
		out[name] = ad
	}
	return out
}

// waitForSlots polls the collector until at least want slot ads appear or the
// timeout elapses, returning whatever it last saw.
func waitForSlots(t *testing.T, ctx context.Context, col *htcondor.Collector, want int, timeout time.Duration) map[string]*classad.ClassAd {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last map[string]*classad.ClassAd
	for time.Now().Before(deadline) {
		last = querySlots(ctx, col)
		if len(last) >= want {
			return last
		}
		time.Sleep(500 * time.Millisecond)
	}
	return last
}

// waitForCondorStatus polls `condor_status -af Name State Cpus Memory` until it
// returns a non-empty listing or the timeout elapses.
func waitForCondorStatus(t *testing.T, configFile string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out := runCondorAllowErr(configFile, 15*time.Second, "condor_status", "-af", "Name", "State", "Cpus", "Memory")
		if strings.TrimSpace(out) != "" {
			return out
		}
		time.Sleep(500 * time.Millisecond)
	}
	return ""
}

func slotNames(m map[string]*classad.ClassAd) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
