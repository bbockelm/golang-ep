package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	hstartd "github.com/bbockelm/golang-htcondor/startd"

	"github.com/bbockelm/golang-ap/shadow"
	"github.com/bbockelm/golang-ep/internal/persist"
)

// TestStage6Process runs the Stage-4 claim/activate/file-transfer flow with
// STARTER_MODE=process: the startd spawns a SEPARATE condor_starter binary,
// dials it over a per-claim Unix socket, and hands the shadow syscall connection
// across via SCM_RIGHTS + exported cedar crypto state. It asserts:
//
//	(1) the job runs in a DISTINCT starter process (its pid != the startd's, the
//	    starter alive during the run) that writes its own StarterLog;
//	(2) the file-transfer job completes with correct outputs returned to the Iwd;
//	(3) the sandbox `.exit` marker records waitpid status 0 / reason JOB_EXITED=100;
//	(4) the persist claim store round-trips (queried cross-process after shutdown);
//	(5) the slot cycles Claimed/Busy -> Claimed/Idle -> Unclaimed;
//	(6) FAILURE VARIANT: kill -9 the starter mid-job -> the startd reaps it and
//	    the slot returns to Claimed/Idle (no wedge).
func TestStage6Process(t *testing.T) {
	for _, tool := range []string{"condor_master", "condor_status"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()
	startdBin := filepath.Join(tmp, fmt.Sprintf("golang-ep-startd-s6-%d", os.Getpid()))
	starterBin := filepath.Join(tmp, fmt.Sprintf("golang-ep-starter-s6-%d", os.Getpid()))
	buildBin(t, startdBin, "../cmd/startd")
	buildBin(t, starterBin, "../cmd/starter")

	executeDir := filepath.Join(tmp, "execute")
	if err := os.MkdirAll(executeDir, 0o755); err != nil {
		t.Fatalf("mkdir execute: %v", err)
	}
	// SHORT /tmp dirs for the per-claim sockets and the claim store: macOS caps
	// unix socket paths near 104 bytes, and t.TempDir() is already long. These
	// survive the harness shutdown so we can read the store cross-process after.
	shortBase, err := os.MkdirTemp("/tmp", "ep6")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shortBase) })
	sockDir := filepath.Join(shortBase, "s")
	claimsDir := filepath.Join(shortBase, "c")

	const aliveInterval = 2
	extra := fmt.Sprintf(`
DAEMON_LIST = MASTER, COLLECTOR, STARTD
STARTD = %s
STARTD_LOG = $(LOG)/StartdLog
STARTD_DEBUG = D_FULLDEBUG
STARTD_ADDRESS_FILE = $(LOG)/.startd_address

NUM_CPUS = 1
MEMORY = 512
NUM_SLOTS = 1
UPDATE_INTERVAL = 5
EXECUTE = %s
STARTER_UPDATE_INTERVAL = 2

STARTER_MODE = process
STARTER = %s
EP_STARTER_SOCKET_DIR = %s
EP_CLAIMS_DIR = %s
KILLING_TIMEOUT = 5

SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = FS
SEC_CLIENT_AUTHENTICATION_METHODS = FS
SEC_DEFAULT_CRYPTO_METHODS = AES
`, startdBin, executeDir, starterBin, sockDir, claimsDir)

	h := htcondor.SetupCondorHarnessWithConfig(t, extra)
	shutdownOnce := false
	shutdown := func() {
		if !shutdownOnce {
			shutdownOnce = true
			h.Shutdown()
		}
	}
	defer shutdown()
	logDir := h.GetLogDir()

	prevConfig, hadConfig := os.LookupEnv("CONDOR_CONFIG")
	_ = os.Setenv("CONDOR_CONFIG", h.GetConfigFile())
	htcondor.ReloadDefaultConfig()
	t.Cleanup(func() {
		if hadConfig {
			_ = os.Setenv("CONDOR_CONFIG", prevConfig)
		} else {
			_ = os.Unsetenv("CONDOR_CONFIG")
		}
		htcondor.ReloadDefaultConfig()
	})

	dumpAllLogs := func() {
		for _, name := range []string{"StartdLog", "MasterLog", "CollectorLog"} {
			dumpLog(t, filepath.Join(logDir, name))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	col := htcondor.NewCollector(h.GetCollectorAddr())

	if slots := waitForSlots(t, ctx, col, 1, 60*time.Second); len(slots) < 1 {
		dumpAllLogs()
		t.Fatal("slot never advertised")
	}

	claimID, slotName := waitForPrivateClaimID(t, ctx, h.GetCollectorAddr(), "", 45*time.Second)
	if claimID == "" {
		dumpAllLogs()
		t.Fatal("could not obtain a ClaimId from the startd private ads")
	}
	stub := newStubSchedd(t, claimID, aliveInterval)

	// Shadow-side file-transfer endpoint.
	ftLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen (ft endpoint): %v", err)
	}
	defer func() { _ = ftLn.Close() }()
	endpoint := shadow.NewEndpoint(security.NewSessionCache(), nil, t.Logf)
	go func() { _ = endpoint.Serve(ctx, ftLn) }()
	for i := 0; i < 100 && endpoint.Sinful() == ""; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if endpoint.Sinful() == "" {
		t.Fatal("file-transfer endpoint never reported its sinful address")
	}

	whoami := "stage6user"
	if u, err := user.Current(); err == nil && u.Username != "" {
		whoami = u.Username
	}
	const inputContent = "hello-from-stage6-process"
	iwd, jobAd := stage4TransferJobAd(t, whoami, inputContent, 8)

	sc, err := hstartd.New(claimID, nil)
	if err != nil {
		t.Fatalf("startd.New: %v", err)
	}
	res, err := sc.RequestClaim(ctx, &hstartd.ClaimRequest{
		RequestAd:     jobAd,
		SchedulerAddr: stub.addr,
		AliveInterval: aliveInterval,
		ScheddName:    "golang-ep-stage6@127.0.0.1",
	})
	if err != nil || !res.OK {
		dumpAllLogs()
		t.Fatalf("REQUEST_CLAIM failed: err=%v res=%+v", err, res)
	}

	ac, err := sc.ActivateClaim(ctx, jobAd, nil)
	if err != nil {
		dumpAllLogs()
		t.Fatalf("ACTIVATE_CLAIM: %v", err)
	}
	events := &eventRecorder{}
	sh, err := shadow.New(ac.Stream(), ac, shadow.Config{
		JobAd:            jobAd,
		ClaimID:          claimID,
		TransferEndpoint: endpoint,
		ShadowAddr:       stub.addr,
		Startd:           sc,
		KeepClaim:        true,
		OnEvent:          func(e shadow.Event) { events.record(e) },
		Logf:             t.Logf,
	})
	if err != nil {
		dumpAllLogs()
		t.Fatalf("shadow.New: %v", err)
	}
	type runOut struct {
		res *shadow.Result
		err error
	}
	runCh := make(chan runOut, 1)
	go func() {
		r, err := sh.Run(ctx)
		runCh <- runOut{r, err}
	}()

	// (1) During the run the slot is Claimed/Busy and a DISTINCT starter process
	// exists. The sandbox dir name embeds the STARTD's pid (dir_<pid>_slotN_seq);
	// the StarterLog inside carries the STARTER's own pid.
	if !waitForCollectorSlot(t, ctx, col, slotName, 60*time.Second, func(ad *classad.ClassAd) string {
		if v, _ := ad.EvaluateAttrString("State"); v != "Claimed" {
			return fmt.Sprintf("State=%q", v)
		}
		if v, _ := ad.EvaluateAttrString("Activity"); v != "Busy" {
			return fmt.Sprintf("Activity=%q", v)
		}
		return ""
	}) {
		dumpAllLogs()
		t.Fatal("collector never showed Claimed/Busy")
	}

	sandbox, startdPid := waitForSandbox(t, executeDir, 20*time.Second)
	if sandbox == "" {
		dumpAllLogs()
		t.Fatal("no starter sandbox appeared (process starter did not run)")
	}
	starterPid := waitForStarterPid(t, filepath.Join(logDir, "StartdLog"), 20*time.Second)
	if starterPid <= 0 {
		t.Fatalf("could not read starter pid from StartdLog")
	}
	if starterPid == startdPid {
		t.Fatalf("starter pid %d == startd pid %d: starter did not run as a distinct process", starterPid, startdPid)
	}
	if err := syscall.Kill(starterPid, 0); err != nil {
		t.Errorf("starter pid %d not alive during the run: %v", starterPid, err)
	}
	t.Logf("distinct process starter: startd pid %d, starter pid %d, sandbox %s", startdPid, starterPid, sandbox)

	// Persistence is being written during the Busy phase.
	if ents, _ := os.ReadDir(claimsDir); len(ents) == 0 {
		t.Errorf("claim store dir %s empty during the run (persistence not wired)", claimsDir)
	}

	var out runOut
	select {
	case out = <-runCh:
	case <-ctx.Done():
		dumpAllLogs()
		t.Fatal("shadow.Run did not finish")
	}
	if out.err != nil {
		dumpAllLogs()
		t.Fatalf("shadow.Run: %v", out.err)
	}
	if !events.saw(shadow.EventJobExit) {
		t.Error("shadow never observed job_exit")
	}
	if code, ok := out.res.ExitCode(); !ok || code != 0 {
		dumpAllLogs()
		t.Fatalf("job exit code = %d (ok=%v), want 0", code, ok)
	}
	if out.res.ExitStatus != 0 || out.res.Reason != shadow.JobExited {
		t.Errorf("job_exit(status=%d, reason=%d), want (0, %d)", out.res.ExitStatus, out.res.Reason, shadow.JobExited)
	}

	// (2) Outputs returned to the Iwd.
	gotResult, err := os.ReadFile(filepath.Join(iwd, "result.txt"))
	if err != nil {
		dumpAllLogs()
		t.Fatalf("result.txt not returned to Iwd: %v", err)
	}
	if want := "RESULT:" + inputContent + "\n"; string(gotResult) != want {
		t.Errorf("result.txt = %q, want %q", gotResult, want)
	}

	// (3) The sandbox .exit marker: status 0, reason JOB_EXITED=100.
	assertExitMarker(t, sandbox, 0, 100)

	// (5) Slot back to Claimed/Idle, then release -> Unclaimed.
	if !waitForCollectorSlot(t, ctx, col, slotName, 30*time.Second, idleCheck) {
		dumpAllLogs()
		t.Fatal("collector never showed Claimed/Idle after the run")
	}
	if err := sc.ReleaseClaim(ctx); err != nil {
		dumpAllLogs()
		t.Fatalf("ReleaseClaim: %v", err)
	}
	if !waitForCollectorSlot(t, ctx, col, slotName, 30*time.Second, unclaimedCheck) {
		dumpAllLogs()
		t.Fatal("collector never showed Unclaimed after release")
	}
	t.Logf("slot %s released back to Unclaimed", slotName)

	// (6) FAILURE VARIANT: kill -9 the starter mid-job; the startd must reap it
	// and return the slot to Claimed/Idle with no wedge.
	newClaimID, _ := waitForFreshClaimID(t, ctx, h.GetCollectorAddr(), slotName, claimID, 30*time.Second)
	if newClaimID == "" {
		dumpAllLogs()
		t.Fatal("no fresh claim id after release")
	}
	stub2 := newStubSchedd(t, newClaimID, aliveInterval)
	_, longAd := stage4TransferJobAd(t, whoami, "kill9-input", 120) // long job so we can kill mid-run

	sc2, err := hstartd.New(newClaimID, nil)
	if err != nil {
		t.Fatalf("startd.New (kill variant): %v", err)
	}
	res, err = sc2.RequestClaim(ctx, &hstartd.ClaimRequest{
		RequestAd:     longAd,
		SchedulerAddr: stub2.addr,
		AliveInterval: aliveInterval,
	})
	if err != nil || !res.OK {
		dumpAllLogs()
		t.Fatalf("REQUEST_CLAIM (kill variant): err=%v res=%+v", err, res)
	}
	ac2, err := sc2.ActivateClaim(ctx, longAd, nil)
	if err != nil {
		dumpAllLogs()
		t.Fatalf("ACTIVATE_CLAIM (kill variant): %v", err)
	}
	sh2, err := shadow.New(ac2.Stream(), ac2, shadow.Config{
		JobAd:            longAd,
		ClaimID:          newClaimID,
		TransferEndpoint: endpoint,
		ShadowAddr:       stub2.addr,
		Startd:           sc2,
		KeepClaim:        true,
		Logf:             t.Logf,
	})
	if err != nil {
		dumpAllLogs()
		t.Fatalf("shadow.New (kill variant): %v", err)
	}
	go func() { _, _ = sh2.Run(ctx) }()

	if !waitForCollectorSlot(t, ctx, col, slotName, 60*time.Second, busyCheck) {
		dumpAllLogs()
		t.Fatal("collector never showed Claimed/Busy (kill variant)")
	}
	starterPid2 := waitForStarterPidExcluding(t, filepath.Join(logDir, "StartdLog"), starterPid, 20*time.Second)
	if starterPid2 <= 0 {
		t.Fatalf("could not read kill-variant starter pid from StartdLog")
	}
	t.Logf("kill -9 the process starter pid %d mid-job", starterPid2)
	if err := syscall.Kill(starterPid2, syscall.SIGKILL); err != nil {
		t.Fatalf("kill -9 starter %d: %v", starterPid2, err)
	}
	// The startd must reap the dead starter and un-wedge the slot to Claimed/Idle.
	if !waitForCollectorSlot(t, ctx, col, slotName, 60*time.Second, idleCheck) {
		dumpAllLogs()
		t.Fatalf("slot %s wedged after kill -9 of the starter (want Claimed/Idle)", slotName)
	}
	t.Logf("startd reaped the killed starter; slot back to Claimed/Idle (no wedge)")
	if err := sc2.ReleaseClaim(ctx); err != nil {
		t.Fatalf("ReleaseClaim (kill variant): %v", err)
	}

	// (4) Persist store round-trips CROSS-PROCESS after the startd exits. Each
	// Put msync'd its record, so the slot's claim record is on disk regardless of
	// a clean close.
	shutdown()
	assertClaimStoreRoundTrips(t, claimsDir, slotName)

	t.Log("Stage 6 OK: distinct process starter, FT job completed, .exit marker, persist round-trip, Busy/Idle cycle, kill -9 no-wedge")
}

// --- Stage-6 helpers ---

func idleCheck(ad *classad.ClassAd) string {
	if v, _ := ad.EvaluateAttrString("State"); v != "Claimed" {
		return fmt.Sprintf("State=%q", v)
	}
	if v, _ := ad.EvaluateAttrString("Activity"); v != "Idle" {
		return fmt.Sprintf("Activity=%q", v)
	}
	return ""
}

func busyCheck(ad *classad.ClassAd) string {
	if v, _ := ad.EvaluateAttrString("State"); v != "Claimed" {
		return fmt.Sprintf("State=%q", v)
	}
	if v, _ := ad.EvaluateAttrString("Activity"); v != "Busy" {
		return fmt.Sprintf("Activity=%q", v)
	}
	return ""
}

func unclaimedCheck(ad *classad.ClassAd) string {
	if v, _ := ad.EvaluateAttrString("State"); v != "Unclaimed" {
		return fmt.Sprintf("State=%q", v)
	}
	return ""
}

func buildBin(t *testing.T, out, pkg string) {
	t.Helper()
	build := exec.Command("go", "build", "-buildvcs=false", "-o", out, pkg)
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building %s: %v\n%s", pkg, err, b)
	}
}

// waitForSandbox returns the newest EXECUTE/dir_<startdpid>_* job sandbox (the
// one holding the transferred input job.sh), plus the STARTD pid embedded in the
// dir name. The starter log lives OUTSIDE the sandbox (so it does not pollute
// output transfer), so we identify the sandbox by its transferred input.
func waitForSandbox(t *testing.T, executeDir string, timeout time.Duration) (string, int) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	dirRe := regexp.MustCompile(`^dir_(\d+)_`)
	for time.Now().Before(deadline) {
		ents, _ := os.ReadDir(executeDir)
		var newest string
		var newestMod time.Time
		var pid int
		for _, e := range ents {
			if !e.IsDir() || !strings.HasPrefix(e.Name(), "dir_") {
				continue
			}
			path := filepath.Join(executeDir, e.Name())
			if _, err := os.Stat(filepath.Join(path, "job.sh")); err != nil {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			if newest == "" || info.ModTime().After(newestMod) {
				newest, newestMod = path, info.ModTime()
				if m := dirRe.FindStringSubmatch(e.Name()); m != nil {
					pid, _ = strconv.Atoi(m[1])
				}
			}
		}
		if newest != "" {
			return newest, pid
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "", 0
}

var starterPidRe = regexp.MustCompile(`starter_pid=(\d+)`)

// waitForStarterPid reads the LATEST starter_pid the startd logged (its
// "ACTIVATE_CLAIM accepted"/"starter hello" lines), which identifies the process
// starter's pid.
func waitForStarterPid(t *testing.T, startdLog string, timeout time.Duration) int {
	t.Helper()
	return waitForStarterPidExcluding(t, startdLog, 0, timeout)
}

// waitForStarterPidExcluding waits until the startd logs a starter_pid different
// from exclude (used to pick up the SECOND activation's starter in the kill
// variant), returning it.
func waitForStarterPidExcluding(t *testing.T, startdLog string, exclude int, timeout time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(startdLog)
		matches := starterPidRe.FindAllStringSubmatch(string(data), -1)
		for i := len(matches) - 1; i >= 0; i-- {
			pid, _ := strconv.Atoi(matches[i][1])
			if pid > 0 && pid != exclude {
				return pid
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return 0
}

func assertExitMarker(t *testing.T, sandbox string, wantStatus, wantReason int) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(sandbox, ".exit"))
	if err != nil {
		t.Fatalf(".exit marker not written to sandbox %s: %v", sandbox, err)
	}
	var m struct {
		WaitpidStatus int `json:"waitpid_status"`
		Reason        int `json:"reason"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parsing .exit marker %q: %v", data, err)
	}
	if m.WaitpidStatus != wantStatus || m.Reason != wantReason {
		t.Errorf(".exit marker = {status:%d reason:%d}, want {status:%d reason:%d}",
			m.WaitpidStatus, m.Reason, wantStatus, wantReason)
	}
}

func assertClaimStoreRoundTrips(t *testing.T, claimsDir, slotName string) {
	t.Helper()
	st, err := persist.Open(claimsDir)
	if err != nil {
		t.Fatalf("reopening claim store %s cross-process: %v", claimsDir, err)
	}
	defer func() { _ = st.Close() }()
	list := st.List()
	if len(list) == 0 {
		t.Fatalf("claim store has no records after the lifecycle")
	}
	rec, ok := st.Get(slotName)
	if !ok {
		t.Fatalf("claim store has no record for slot %s (have %d records)", slotName, len(list))
	}
	if rec.ClaimID == "" {
		t.Errorf("persisted record for %s has empty ClaimID", slotName)
	}
	if rec.State == "" {
		t.Errorf("persisted record for %s has empty State", slotName)
	}
	t.Logf("claim store round-trip: slot=%s state=%s/%s public_claim=%s",
		rec.SlotName, rec.State, rec.Activity, rec.PublicClaimID)
}
