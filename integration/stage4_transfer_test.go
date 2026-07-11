package integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	hstartd "github.com/bbockelm/golang-htcondor/startd"

	"github.com/bbockelm/golang-ap/shadow"
)

// TestStage4Transfer proves the Go starter's FILE-TRANSFER CLIENT role end to
// end against the golang-ap shadow's transfer server (the peer proven against
// the stock C++ starter), on top of the Stage-3 claim/activate flow:
//
//	(1) claim id + stub schedd + REQUEST_CLAIM, as in Stage 3;
//	(2) a shadow-side file-transfer Endpoint (FILETRANS_UPLOAD/DOWNLOAD) is
//	    stood up in the test; the shadow injects TransferSocket/TransferKey
//	    into the get_job_info ad and answers get_sec_session_info with the
//	    filetrans session (shadow.Config{ClaimID, TransferEndpoint});
//	(3) ACTIVATE_CLAIM with ShouldTransferFiles="YES": the starter must pull
//	    the input sandbox (script executable + a data file) BEFORE
//	    begin_execution, the job proves the input content flowed by deriving
//	    an output file from it, and after exit the starter must push the
//	    outputs back (result file + captured stdout/stderr) and send
//	    job_termination(-82) before job_exit(0, JOB_EXITED=100);
//	(4) the outputs land in the test's Iwd with the right bytes; the slot
//	    cycles Claimed/Busy -> Claimed/Idle; RELEASE returns it to Unclaimed;
//	(5) failure variant: the input transfer breaks mid-stream (the input file
//	    vanishes after the shadow built its plan) -> the starter reports
//	    job_exit(status 0, reason JOB_NOT_STARTED=108) -- our documented
//	    input-transfer-failure choice -- and the slot returns to Claimed/Idle
//	    (no wedge).
func TestStage4Transfer(t *testing.T) {
	for _, tool := range []string{"condor_master", "condor_status"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()
	binName := fmt.Sprintf("golang-ep-startd-s4-%d", os.Getpid())
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

	// (2) The shadow-side file-transfer endpoint the starter connects back to.
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
	t.Logf("file-transfer endpoint at %s", endpoint.Sinful())

	whoami := "stage4user"
	if u, err := user.Current(); err == nil && u.Username != "" {
		whoami = u.Username
	}
	const inputContent = "hello-from-stage4-shadow"
	// The job sleeps long enough for the collector (UPDATE_INTERVAL=5) to
	// observably show Claimed/Busy, verifies the transferred input's content,
	// and derives an output file from it (proving the bytes flowed both ways).
	iwd, jobAd := stage4TransferJobAd(t, whoami, inputContent, 8)

	sc, err := hstartd.New(claimID, nil)
	if err != nil {
		t.Fatalf("startd.New: %v", err)
	}
	res, err := sc.RequestClaim(ctx, &hstartd.ClaimRequest{
		RequestAd:     jobAd,
		SchedulerAddr: stub.addr,
		AliveInterval: aliveInterval,
		ScheddName:    "golang-ep-stage4@127.0.0.1",
	})
	if err != nil || !res.OK {
		dumpAllLogs()
		t.Fatalf("REQUEST_CLAIM failed: err=%v res=%+v", err, res)
	}
	t.Logf("slot %q claimed; activating with file transfer", slotName)

	// (3) ACTIVATE_CLAIM + the golang-ap shadow WITH its transfer server.
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
		KeepClaim:        true, // assert Claimed/Idle first, release explicitly
		OnEvent: func(e shadow.Event) {
			events.record(e)
			if e.Type == shadow.EventGetJobInfo && e.Ad != nil {
				tk, _ := e.Ad.EvaluateAttrString("TransferKey")
				ts, _ := e.Ad.EvaluateAttrString("TransferSocket")
				t.Logf("get_job_info ad: TransferKey=%q TransferSocket=%q", tk, ts)
			}
		},
		Logf: t.Logf,
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

	// The starter observed the full sequence: begin_execution, then (after the
	// run) job_termination(-82) in the output window, then job_exit(0, 100).
	if !events.saw(shadow.EventBeginExecution) {
		t.Error("shadow never observed begin_execution")
	}
	if !events.saw(shadow.EventJobTermination) {
		t.Error("shadow never observed job_termination (the starter must send -82 after output transfer, before job_exit)")
	}
	if !events.saw(shadow.EventJobExit) {
		t.Error("shadow never observed job_exit")
	}
	if code, ok := out.res.ExitCode(); !ok || code != 0 {
		dumpAllLogs()
		t.Fatalf("job exit code = %d (ok=%v), want 0 (job likely failed its input-content check)", code, ok)
	}
	if out.res.ExitStatus != 0 || out.res.Reason != shadow.JobExited {
		t.Errorf("job_exit(status=%d, reason=%d), want (0, %d)", out.res.ExitStatus, out.res.Reason, shadow.JobExited)
	}
	if out.res.FinalAd == nil {
		t.Error("shadow recorded no job_termination ad")
	}

	// (4) Outputs back in the Iwd with the right bytes.
	gotResult, err := os.ReadFile(filepath.Join(iwd, "result.txt"))
	if err != nil {
		dumpAllLogs()
		t.Fatalf("explicit output file result.txt not returned to Iwd: %v", err)
	}
	if want := "RESULT:" + inputContent + "\n"; string(gotResult) != want {
		t.Errorf("result.txt = %q, want %q", gotResult, want)
	}
	gotStdout, err := os.ReadFile(filepath.Join(iwd, "job.out"))
	if err != nil {
		dumpAllLogs()
		t.Fatalf("captured stdout job.out not returned to Iwd: %v", err)
	}
	if want := "job stdout ok: " + inputContent; !strings.Contains(string(gotStdout), want) {
		t.Errorf("job.out = %q, want it to contain %q", gotStdout, want)
	}
	if _, err := os.Stat(filepath.Join(iwd, "job.err")); err != nil {
		t.Errorf("captured stderr job.err not returned to Iwd: %v", err)
	}
	t.Logf("outputs returned: result.txt + job.out + job.err")

	// Slot back to Claimed/Idle (claim kept), then release -> Unclaimed.
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

	// (5) Failure variant on a FRESH claim: the input transfer breaks
	// mid-stream. The shadow builds its input plan at shadow.New (it stats the
	// files then), so a nonexistent-at-transfer-time input is provoked by
	// deleting the file AFTER shadow.New: the endpoint's lazy Open fails during
	// ServeUpload and the starter's ReceiveStream dies -> the starter must
	// report job_exit(status 0, reason JOB_NOT_STARTED=108) and the slot must
	// return to Claimed/Idle (no wedge).
	newClaimID, _ := waitForFreshClaimID(t, ctx, h.GetCollectorAddr(), slotName, claimID, 30*time.Second)
	if newClaimID == "" {
		dumpAllLogs()
		t.Fatal("no fresh claim id after release")
	}
	stub2 := newStubSchedd(t, newClaimID, aliveInterval)
	iwd2, badAd := stage4TransferJobAd(t, whoami, "doomed-input", 0)

	sc2, err := hstartd.New(newClaimID, nil)
	if err != nil {
		t.Fatalf("startd.New (failure variant): %v", err)
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
	sh2, err := shadow.New(ac2.Stream(), ac2, shadow.Config{
		JobAd:            badAd,
		ClaimID:          newClaimID,
		TransferEndpoint: endpoint,
		Logf:             t.Logf,
	})
	if err != nil {
		dumpAllLogs()
		t.Fatalf("shadow.New (failure variant): %v", err)
	}
	// Break the input transfer: the plan was built (stat) at shadow.New; the
	// bytes are opened lazily at ServeUpload time.
	if err := os.Remove(filepath.Join(iwd2, "input.dat")); err != nil {
		t.Fatalf("removing input.dat: %v", err)
	}
	res2, err := sh2.Run(ctx)
	if err != nil {
		dumpAllLogs()
		t.Fatalf("shadow.Run (failure variant): %v", err)
	}
	// JOB_NOT_STARTED=108: our documented reason for input-transfer failure
	// (the job never started; exit.h's JOB_CXFER_* codes are checkpoint-only).
	if res2.Reason != 108 {
		t.Errorf("input-transfer-failure job_exit reason = %d, want JOB_NOT_STARTED(108)", res2.Reason)
	}
	if res2.ExitStatus != 0 {
		t.Errorf("input-transfer-failure job_exit status = %d, want 0", res2.ExitStatus)
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
		t.Fatalf("slot %s wedged after input-transfer failure (want Claimed/Idle)", slotName)
	}
	if err := sc2.ReleaseClaim(ctx); err != nil {
		t.Fatalf("ReleaseClaim (failure variant): %v", err)
	}
	t.Log("Stage 4 OK: input download before begin_execution, content flowed, outputs + stdio returned, job_termination window, Busy/Idle cycle, input-failure path")
}

// stage4TransferJobAd writes a fresh script executable and an input data file
// into a temp Iwd and returns (iwd, jobAd) for a transfer-enabled job that
// verifies the input content and derives an output file from it. sleepSecs>0
// keeps the job alive long enough for collector-state assertions.
func stage4TransferJobAd(t *testing.T, owner, inputContent string, sleepSecs int) (string, *classad.ClassAd) {
	t.Helper()
	iwd := t.TempDir()

	script := "#!/bin/sh\n" +
		"expected='" + inputContent + "'\n" +
		"got=$(cat input.dat)\n" +
		"if [ \"$got\" != \"$expected\" ]; then\n" +
		"  echo \"MISMATCH: got [$got] want [$expected]\" 1>&2\n" +
		"  exit 17\n" +
		"fi\n" +
		fmt.Sprintf("sleep %d\n", sleepSecs) +
		"echo \"job stdout ok: $got\"\n" +
		"printf 'RESULT:%s\\n' \"$got\" > result.txt\n" +
		"exit 0\n"
	if err := os.WriteFile(filepath.Join(iwd, "job.sh"), []byte(script), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	if err := os.WriteFile(filepath.Join(iwd, "input.dat"), []byte(inputContent), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	ad := classad.New()
	_ = ad.Set("MyType", "Job")
	_ = ad.Set("ClusterId", int64(1))
	_ = ad.Set("ProcId", int64(0))
	_ = ad.Set("GlobalJobId", fmt.Sprintf("golang-ep-stage4#1.0#%d", time.Now().Unix()))
	_ = ad.Set("JobUniverse", int64(5))
	_ = ad.Set("Owner", owner)
	_ = ad.Set("User", owner+"@example.net")
	_ = ad.Set("Cmd", filepath.Join(iwd, "job.sh"))
	_ = ad.Set("Iwd", iwd)
	_ = ad.Set("In", "/dev/null")
	_ = ad.Set("Out", "job.out")
	_ = ad.Set("Err", "job.err")
	_ = ad.Set("ShouldTransferFiles", "YES")
	_ = ad.Set("WhenToTransferOutput", "ON_EXIT")
	_ = ad.Set("TransferExecutable", true)
	_ = ad.Set("TransferInput", "input.dat")
	_ = ad.Set("JobStatus", int64(2))
	_ = ad.Set("JobLeaseDuration", int64(1200))
	_ = ad.Set("RequestCpus", int64(1))
	_ = ad.Set("RequestMemory", int64(128))
	_ = ad.Set("RequestDisk", int64(1024))
	_ = ad.Set("Requirements", true)
	return iwd, ad
}
