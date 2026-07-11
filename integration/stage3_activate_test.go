package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
	hstartd "github.com/bbockelm/golang-htcondor/startd"

	"github.com/bbockelm/golang-ap/shadow"
)

// TestStage3Activate proves the Go startd's Stage-3 activation surface end to
// end against a real condor_master + C++ collector, with this test process
// acting as the schedd AND (via the embedded golang-ap shadow -- the syscall
// server proven against the C++ starter) the shadow:
//
//	(1) harvest a claim id, stand up the stub schedd (ALIVE), REQUEST_CLAIM;
//	(2) ACTIVATE_CLAIM with a hand-built no-transfer vanilla job ad; the
//	    activation socket is kept open by the startd (socket takeover) and
//	    becomes the starter's remote-syscall channel;
//	(3) wrap that socket in the golang-ap shadow: it must observe
//	    begin_execution then job_exit(status 0, reason JOB_EXITED=100), the
//	    marker file the job wrote must exist with the right content, and the
//	    collector must show Claimed/Busy during the run;
//	(4) after the run the slot returns to Claimed/Idle (claim kept), and
//	    RELEASE_CLAIM returns it to Unclaimed;
//	(5) failure variant: a job whose Cmd does not exist gets
//	    job_exit(reason JOB_EXEC_FAILED=110) and the slot returns to
//	    Claimed/Idle (no wedge).
func TestStage3Activate(t *testing.T) {
	for _, tool := range []string{"condor_master", "condor_status"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()
	binName := fmt.Sprintf("golang-ep-startd-s3-%d", os.Getpid())
	startdBin := filepath.Join(tmp, binName)
	build := exec.Command("go", "build", "-buildvcs=false", "-o", startdBin, "../cmd/startd")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building golang-ep startd: %v\n%s", err, out)
	}
	executeDir := filepath.Join(tmp, "execute")
	if err := os.MkdirAll(executeDir, 0o755); err != nil {
		t.Fatalf("mkdir execute: %v", err)
	}

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

SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = FS
SEC_CLIENT_AUTHENTICATION_METHODS = FS
SEC_DEFAULT_CRYPTO_METHODS = AES
`, startdBin, executeDir)

	h := htcondor.SetupCondorHarnessWithConfig(t, extra)
	defer h.Shutdown()
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

	// (1) Claim id + stub schedd + REQUEST_CLAIM.
	claimID, slotName := waitForPrivateClaimID(t, ctx, h.GetCollectorAddr(), "", 45*time.Second)
	if claimID == "" {
		dumpAllLogs()
		t.Fatal("could not obtain a ClaimId from the startd private ads")
	}
	t.Logf("got claim id for slot %q", slotName)
	stub := newStubSchedd(t, claimID, aliveInterval)

	whoami := "stage3user"
	if u, err := user.Current(); err == nil && u.Username != "" {
		whoami = u.Username
	}
	iwd := t.TempDir()
	marker := filepath.Join(iwd, "marker.txt")
	jobAd := stage3JobAd(whoami, iwd)
	// The job sleeps long enough for the collector (UPDATE_INTERVAL=5, plus the
	// startd's immediate transition re-advertise) to observably show
	// Claimed/Busy, then writes the marker.
	_ = jobAd.Set("Arguments", fmt.Sprintf("-c 'sleep 8; printf stage3-ok > %s; exit 0'", marker))

	sc, err := hstartd.New(claimID, nil)
	if err != nil {
		t.Fatalf("startd.New: %v", err)
	}
	res, err := sc.RequestClaim(ctx, &hstartd.ClaimRequest{
		RequestAd:     jobAd,
		SchedulerAddr: stub.addr,
		AliveInterval: aliveInterval,
		ScheddName:    "golang-ep-stage3@127.0.0.1",
	})
	if err != nil || !res.OK {
		dumpAllLogs()
		t.Fatalf("REQUEST_CLAIM failed: err=%v res=%+v", err, res)
	}
	t.Logf("slot %q claimed; activating", slotName)

	// (2) ACTIVATE_CLAIM: the same socket becomes the syscall channel.
	ac, err := sc.ActivateClaim(ctx, jobAd, nil)
	if err != nil {
		dumpAllLogs()
		t.Fatalf("ACTIVATE_CLAIM: %v", err)
	}

	// (3) Embed the golang-ap shadow as the syscall server, recording events.
	events := &eventRecorder{}
	sh, err := shadow.New(ac.Stream(), ac, shadow.Config{
		JobAd:      jobAd,
		ShadowAddr: stub.addr,
		Startd:     sc,
		KeepClaim:  true, // wind down with DEACTIVATE (our stub) but keep the claim: we assert Claimed/Idle, then release explicitly
		OnEvent:    events.record,
		Logf:       t.Logf,
	})
	if err != nil {
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

	// The collector must show Claimed/Busy while the job (8s) runs.
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
		t.Fatalf("collector never showed %s Claimed/Busy during the run", slotName)
	}
	t.Logf("collector shows %s Claimed/Busy", slotName)

	var out runOut
	select {
	case out = <-runCh:
	case <-ctx.Done():
		dumpAllLogs()
		t.Fatal("shadow.Run did not finish")
	}
	if out.err != nil {
		dumpAllLogs()
		t.Fatalf("shadow.Run: %v (result %+v)", out.err, out.res)
	}

	// The shadow observed begin_execution then job_exit(0, JOB_EXITED).
	if !events.saw(shadow.EventBeginExecution) {
		t.Error("shadow never observed begin_execution")
	}
	if !events.saw(shadow.EventJobExit) {
		t.Error("shadow never observed job_exit")
	}
	if code, ok := out.res.ExitCode(); !ok || code != 0 {
		dumpAllLogs()
		t.Errorf("job exit code = %d (ok=%v), want 0", code, ok)
	}
	if out.res.ExitStatus != 0 || out.res.Reason != shadow.JobExited {
		t.Errorf("job_exit(status=%d, reason=%d), want (0, %d)", out.res.ExitStatus, out.res.Reason, shadow.JobExited)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "stage3-ok" {
		dumpAllLogs()
		t.Errorf("marker file: data=%q err=%v, want \"stage3-ok\"", data, err)
	}
	t.Logf("job ran to completion: status=%d reason=%d", out.res.ExitStatus, out.res.Reason)

	// (4) Slot back to Claimed/Idle (claim kept), then release -> Unclaimed.
	if !waitForCollectorSlot(t, ctx, col, slotName, 30*time.Second, func(ad *classad.ClassAd) string {
		if v, _ := ad.EvaluateAttrString("State"); v != "Claimed" {
			return fmt.Sprintf("State=%q", v)
		}
		if v, _ := ad.EvaluateAttrString("Activity"); v != "Idle" {
			return fmt.Sprintf("Activity=%q", v)
		}
		return ""
	}) {
		dumpAllLogs()
		t.Fatalf("collector never showed %s Claimed/Idle after the run", slotName)
	}
	if err := sc.ReleaseClaim(ctx); err != nil {
		dumpAllLogs()
		t.Fatalf("ReleaseClaim: %v", err)
	}
	if !waitForCollectorSlot(t, ctx, col, slotName, 30*time.Second, func(ad *classad.ClassAd) string {
		if v, _ := ad.EvaluateAttrString("State"); v != "Unclaimed" {
			return fmt.Sprintf("State=%q", v)
		}
		return ""
	}) {
		dumpAllLogs()
		t.Fatalf("collector never showed %s Unclaimed after release", slotName)
	}
	t.Logf("slot %s released back to Unclaimed", slotName)

	// (5) Failure variant on a FRESH claim: exec failure -> JOB_EXEC_FAILED=110
	// and the slot returns to Claimed/Idle (no wedge).
	newClaimID, _ := waitForFreshClaimID(t, ctx, h.GetCollectorAddr(), slotName, claimID, 30*time.Second)
	if newClaimID == "" {
		dumpAllLogs()
		t.Fatal("no fresh claim id after release")
	}
	stub2 := newStubSchedd(t, newClaimID, aliveInterval)
	badAd := stage3JobAd(whoami, iwd)
	_ = badAd.Set("Cmd", "/nonexistent/stage3-no-such-binary")

	sc2, err := hstartd.New(newClaimID, nil)
	if err != nil {
		t.Fatalf("startd.New (fresh claim): %v", err)
	}
	res, err = sc2.RequestClaim(ctx, &hstartd.ClaimRequest{
		RequestAd:     badAd,
		SchedulerAddr: stub2.addr,
		AliveInterval: aliveInterval,
	})
	if err != nil || !res.OK {
		dumpAllLogs()
		t.Fatalf("REQUEST_CLAIM (failure variant): err=%v res=%+v", err, res)
	}
	ac2, err := sc2.ActivateClaim(ctx, badAd, nil)
	if err != nil {
		dumpAllLogs()
		t.Fatalf("ACTIVATE_CLAIM (failure variant): %v", err)
	}
	sh2, err := shadow.New(ac2.Stream(), ac2, shadow.Config{JobAd: badAd, Logf: t.Logf})
	if err != nil {
		t.Fatalf("shadow.New (failure variant): %v", err)
	}
	res2, err := sh2.Run(ctx)
	if err != nil {
		dumpAllLogs()
		t.Fatalf("shadow.Run (failure variant): %v", err)
	}
	// JOB_EXEC_FAILED=110: our documented choice for exec failures
	// (JOB_NOT_STARTED=108 is reserved for pre-exec infrastructure failures).
	if res2.Reason != 110 {
		t.Errorf("exec-failure job_exit reason = %d, want JOB_EXEC_FAILED(110)", res2.Reason)
	}
	if !waitForCollectorSlot(t, ctx, col, slotName, 30*time.Second, func(ad *classad.ClassAd) string {
		if v, _ := ad.EvaluateAttrString("State"); v != "Claimed" {
			return fmt.Sprintf("State=%q", v)
		}
		if v, _ := ad.EvaluateAttrString("Activity"); v != "Idle" {
			return fmt.Sprintf("Activity=%q", v)
		}
		return ""
	}) {
		dumpAllLogs()
		t.Fatalf("slot %s wedged after exec failure (want Claimed/Idle)", slotName)
	}
	if err := sc2.ReleaseClaim(ctx); err != nil {
		t.Fatalf("ReleaseClaim (failure variant): %v", err)
	}
	t.Log("Stage 3 OK: activate, socket takeover, syscall sequence, job run, Busy/Idle cycle, exec-failure path")
}

// stage3JobAd builds the hand-built no-transfer vanilla job ad.
func stage3JobAd(owner, iwd string) *classad.ClassAd {
	ad := classad.New()
	_ = ad.Set("MyType", "Job")
	_ = ad.Set("ClusterId", int64(1))
	_ = ad.Set("ProcId", int64(0))
	_ = ad.Set("GlobalJobId", fmt.Sprintf("golang-ep-stage3#1.0#%d", time.Now().Unix()))
	_ = ad.Set("JobUniverse", int64(5))
	_ = ad.Set("Owner", owner)
	_ = ad.Set("User", owner+"@example.net")
	_ = ad.Set("Cmd", "/bin/sh")
	_ = ad.Set("Arguments", "-c 'exit 0'")
	_ = ad.Set("Iwd", iwd)
	_ = ad.Set("In", "/dev/null")
	_ = ad.Set("Out", "job.out")
	_ = ad.Set("Err", "job.err")
	_ = ad.Set("ShouldTransferFiles", "NO")
	_ = ad.Set("TransferExecutable", false)
	_ = ad.Set("JobStatus", int64(2))
	_ = ad.Set("JobLeaseDuration", int64(1200))
	_ = ad.Set("RequestCpus", int64(1))
	_ = ad.Set("RequestMemory", int64(128))
	_ = ad.Set("RequestDisk", int64(1024))
	_ = ad.Set("Requirements", true)
	return ad
}

// eventRecorder collects shadow event types thread-safely.
type eventRecorder struct {
	mu    sync.Mutex
	types []string
}

func (r *eventRecorder) record(e shadow.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.types = append(r.types, e.Type)
}

func (r *eventRecorder) saw(typ string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, tt := range r.types {
		if tt == typ {
			return true
		}
	}
	return false
}
