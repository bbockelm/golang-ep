package integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	hstartd "github.com/bbockelm/golang-htcondor/startd"

	"github.com/bbockelm/golang-ap/shadow"
)

// TestStage7Restart proves Stage-7 restart survival with STARTER_MODE=process in
// two variants sharing one harness:
//
//  1. CA reconnect path: a long job runs under a process starter; the shadow
//     DETACHES (drops its syscall socket, leaves the claim + job intact), then a
//     fresh shadow re-attaches via the two CA_CMD commands -- CA_LOCATE_STARTER
//     to the startd (finds the starter) and CA_RECONNECT_JOB to the starter
//     (adopts the connection as the new syscall socket) -- and drives the job to
//     completion with correct output. This exercises BOTH CA servers end to end
//     through golang-ap's proven shadow reconnect client.
//
//  2. Startd restart (fast, < lease): a long job runs under a process starter;
//     the Go startd is kill -9'd mid-job and condor_master restarts it. The
//     surviving starter keeps the job running (pid unchanged); the new startd
//     re-adopts it from the persisted claim store (redial + Reattach/Hello) and
//     the job completes with correct output, the slot returning to Claimed/Idle
//     then Unclaimed on release. The embedded shadow stays alive across the gap.
func TestStage7Restart(t *testing.T) {
	for _, tool := range []string{"condor_master", "condor_status"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()
	startdBin := filepath.Join(tmp, fmt.Sprintf("golang-ep-startd-s7-%d", os.Getpid()))
	starterBin := filepath.Join(tmp, fmt.Sprintf("golang-ep-starter-s7-%d", os.Getpid()))
	buildBin(t, startdBin, "../cmd/startd")
	buildBin(t, starterBin, "../cmd/starter")

	executeDir := filepath.Join(tmp, "execute")
	if err := os.MkdirAll(executeDir, 0o755); err != nil {
		t.Fatalf("mkdir execute: %v", err)
	}
	shortBase, err := os.MkdirTemp("/tmp", "ep7")
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

# Restart the startd promptly after a kill -9 so re-adoption happens within the
# running job's lifetime.
MASTER_BACKOFF_CONSTANT = 1
MASTER_BACKOFF_FACTOR = 1
MASTER_BACKOFF_CEILING = 2
MASTER_NEW_BINARY_DELAY = 1

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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	col := htcondor.NewCollector(h.GetCollectorAddr())

	if slots := waitForSlots(t, ctx, col, 1, 60*time.Second); len(slots) < 1 {
		dumpAllLogs()
		t.Fatal("slot never advertised")
	}

	whoami := "stage7user"
	if u, err := user.Current(); err == nil && u.Username != "" {
		whoami = u.Username
	}

	// Shared shadow-side file-transfer endpoint.
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

	// =====================================================================
	// Variant 1: CA reconnect path (detach + shadow-driven reconnect).
	// =====================================================================
	t.Run("CAReconnect", func(t *testing.T) {
		claimID, slotName := waitForPrivateClaimID(t, ctx, h.GetCollectorAddr(), "", 45*time.Second)
		if claimID == "" {
			dumpAllLogs()
			t.Fatal("no ClaimId for CA reconnect variant")
		}
		stub := newStubSchedd(t, claimID, aliveInterval)
		iwd, jobAd := stage4TransferJobAd(t, whoami, "hello-reconnect", 25)

		sc, err := hstartd.New(claimID, nil)
		if err != nil {
			t.Fatalf("startd.New: %v", err)
		}
		if res, err := sc.RequestClaim(ctx, &hstartd.ClaimRequest{
			RequestAd: jobAd, SchedulerAddr: stub.addr, AliveInterval: aliveInterval,
			ScheddName: "golang-ep-stage7@127.0.0.1",
		}); err != nil || !res.OK {
			dumpAllLogs()
			t.Fatalf("REQUEST_CLAIM: err=%v res=%+v", err, res)
		}
		ac, err := sc.ActivateClaim(ctx, jobAd, nil)
		if err != nil {
			dumpAllLogs()
			t.Fatalf("ACTIVATE_CLAIM: %v", err)
		}

		// First shadow: run until the job is executing, then DETACH (drop the
		// syscall socket, keep the claim + job) to simulate a schedd/shadow that
		// stepped away.
		detach := &atomic.Bool{}
		sctx, scancel := context.WithCancel(ctx)
		sh1, err := shadow.New(ac.Stream(), ac, shadow.Config{
			JobAd:            jobAd,
			ClaimID:          claimID,
			TransferEndpoint: endpoint,
			ShadowAddr:       stub.addr,
			Detach:           detach,
			KeepClaim:        true,
			Logf:             t.Logf,
		})
		if err != nil {
			dumpAllLogs()
			t.Fatalf("shadow.New: %v", err)
		}
		run1 := make(chan error, 1)
		go func() { _, e := sh1.Run(sctx); run1 <- e }()

		if !waitForCollectorSlot(t, ctx, col, slotName, 60*time.Second, busyCheck) {
			dumpAllLogs()
			t.Fatal("slot never Claimed/Busy (CA variant)")
		}
		// Let the job get well into execution, then detach.
		time.Sleep(3 * time.Second)
		detach.Store(true)
		scancel()
		select {
		case e := <-run1:
			if e != nil && e != shadow.ErrDetached {
				t.Logf("first shadow returned %v (want ErrDetached)", e)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("first shadow did not detach")
		}
		t.Log("first shadow detached; job still running on the surviving starter")

		// Second shadow: reconnect via CA_LOCATE_STARTER (to the startd) +
		// CA_RECONNECT_JOB (to the starter), then serve to completion.
		gjid, _ := jobAd.EvaluateAttrString("GlobalJobId")
		sh2, err := shadow.NewReconnect(shadow.Config{
			JobAd:            jobAd,
			ClaimID:          claimID,
			TransferEndpoint: endpoint,
			ShadowAddr:       stub.addr,
			ScheddPublicAddr: stub.addr,
			GlobalJobID:      gjid,
			Startd:           sc,
			Logf:             t.Logf,
		})
		if err != nil {
			dumpAllLogs()
			t.Fatalf("shadow.NewReconnect: %v", err)
		}
		res2, err := sh2.RunReconnect(ctx)
		if err != nil {
			dumpAllLogs()
			t.Fatalf("RunReconnect: %v", err)
		}
		if code, ok := res2.ExitCode(); !ok || code != 0 {
			dumpAllLogs()
			t.Fatalf("reconnected job exit code = %d (ok=%v), want 0", code, ok)
		}
		got, err := os.ReadFile(filepath.Join(iwd, "result.txt"))
		if err != nil {
			dumpAllLogs()
			t.Fatalf("result.txt not returned after reconnect: %v", err)
		}
		if want := "RESULT:hello-reconnect\n"; string(got) != want {
			t.Errorf("result.txt = %q, want %q", got, want)
		}
		t.Log("Stage 7 CA reconnect OK: CA_LOCATE_STARTER + CA_RECONNECT_JOB drove the job to completion")
	})

	// =====================================================================
	// Variant 2: startd restart (kill -9 + master restart + re-adoption).
	// =====================================================================
	t.Run("StartdRestart", func(t *testing.T) {
		claimID, slotName := waitForFreshClaimID(t, ctx, h.GetCollectorAddr(), "", "", 40*time.Second)
		if claimID == "" {
			// Any claim id works if no prior one to exclude.
			claimID, slotName = waitForPrivateClaimID(t, ctx, h.GetCollectorAddr(), "", 40*time.Second)
		}
		if claimID == "" {
			dumpAllLogs()
			t.Fatal("no ClaimId for restart variant")
		}
		stub := newStubSchedd(t, claimID, aliveInterval)
		iwd, jobAd := stage4TransferJobAd(t, whoami, "hello-restart", 30)

		sc, err := hstartd.New(claimID, nil)
		if err != nil {
			t.Fatalf("startd.New: %v", err)
		}
		if res, err := sc.RequestClaim(ctx, &hstartd.ClaimRequest{
			RequestAd: jobAd, SchedulerAddr: stub.addr, AliveInterval: aliveInterval,
			ScheddName: "golang-ep-stage7@127.0.0.1",
		}); err != nil || !res.OK {
			dumpAllLogs()
			t.Fatalf("REQUEST_CLAIM: err=%v res=%+v", err, res)
		}
		ac, err := sc.ActivateClaim(ctx, jobAd, nil)
		if err != nil {
			dumpAllLogs()
			t.Fatalf("ACTIVATE_CLAIM: %v", err)
		}
		sh, err := shadow.New(ac.Stream(), ac, shadow.Config{
			JobAd:            jobAd,
			ClaimID:          claimID,
			TransferEndpoint: endpoint,
			ShadowAddr:       stub.addr,
			Startd:           sc,
			KeepClaim:        true,
			Logf:             t.Logf,
		})
		if err != nil {
			dumpAllLogs()
			t.Fatalf("shadow.New: %v", err)
		}
		runCh := make(chan *shadow.Result, 1)
		errCh := make(chan error, 1)
		go func() {
			r, e := sh.Run(ctx)
			if e != nil {
				errCh <- e
				return
			}
			runCh <- r
		}()

		if !waitForCollectorSlot(t, ctx, col, slotName, 60*time.Second, busyCheck) {
			dumpAllLogs()
			t.Fatal("slot never Claimed/Busy (restart variant)")
		}
		starterPid := waitForStarterPid(t, filepath.Join(logDir, "StartdLog"), 20*time.Second)
		if starterPid <= 0 {
			t.Fatal("could not read starter pid before restart")
		}

		// Give persistence a beat to land the Busy record (StarterSocket, GlobalJobId,
		// StarterIpAddr) before killing the startd.
		time.Sleep(1500 * time.Millisecond)

		startdMatch := filepath.Base(startdBin)
		oldStartd := pgrep(t, startdMatch)
		if len(oldStartd) == 0 {
			dumpAllLogs()
			t.Fatal("could not find the startd process to kill")
		}
		t.Logf("kill -9 the Go startd %v (starter %d keeps the job)", oldStartd, starterPid)
		for _, p := range oldStartd {
			if pid, _ := strconv.Atoi(p); pid > 0 {
				_ = exec.Command("kill", "-9", p).Run()
			}
		}

		// condor_master restarts the startd under a fresh pid.
		newPid := waitForNewStartdPid(t, startdMatch, oldStartd, 60*time.Second)
		if newPid == "" {
			dumpAllLogs()
			t.Fatal("condor_master did not restart the startd")
		}
		t.Logf("startd restarted (new pid %s); awaiting re-adoption", newPid)

		// The surviving starter's pid is unchanged (it outlived the startd).
		if !processAlive(starterPid) {
			dumpAllLogs()
			t.Fatalf("starter pid %d died across the startd restart (survival broken)", starterPid)
		}

		// The new startd re-adopts the persisted claim (log marker + slot Busy again).
		if !waitForLogContains(filepath.Join(logDir, "StartdLog"), "re-adopted claim", 60*time.Second) {
			dumpAllLogs()
			t.Fatal("restarted startd never logged re-adoption")
		}
		if !waitForCollectorSlot(t, ctx, col, slotName, 60*time.Second, busyCheck) {
			dumpAllLogs()
			t.Fatal("re-adopted slot never showed Claimed/Busy after restart")
		}
		t.Logf("startd re-adopted the running job on %s (starter pid %d unchanged)", slotName, starterPid)

		// The job runs to completion; the (still-alive) shadow observes job_exit.
		select {
		case r := <-runCh:
			if code, ok := r.ExitCode(); !ok || code != 0 {
				dumpAllLogs()
				t.Fatalf("job exit code = %d (ok=%v), want 0", code, ok)
			}
		case e := <-errCh:
			dumpAllLogs()
			t.Fatalf("shadow.Run errored across the restart: %v", e)
		case <-ctx.Done():
			dumpAllLogs()
			t.Fatal("job never completed after restart")
		}
		got, err := os.ReadFile(filepath.Join(iwd, "result.txt"))
		if err != nil {
			dumpAllLogs()
			t.Fatalf("result.txt not returned after restart: %v", err)
		}
		if want := "RESULT:hello-restart\n"; string(got) != want {
			t.Errorf("result.txt = %q, want %q", got, want)
		}

		// The re-adopted startd saw the starter finish: slot back to Claimed/Idle.
		if !waitForCollectorSlot(t, ctx, col, slotName, 30*time.Second, idleCheck) {
			dumpAllLogs()
			t.Fatal("slot never returned to Claimed/Idle after the job finished post-restart")
		}
		if err := sc.ReleaseClaim(ctx); err != nil {
			t.Fatalf("ReleaseClaim: %v", err)
		}
		if !waitForCollectorSlot(t, ctx, col, slotName, 30*time.Second, unclaimedCheck) {
			dumpAllLogs()
			t.Fatal("slot never returned to Unclaimed after release")
		}
		t.Log("Stage 7 startd-restart OK: starter survived kill -9, startd re-adopted, job completed, slot cycled")
	})
}

// waitForNewStartdPid waits until a startd process appears whose pid is not in
// the excluded set, returning it.
func waitForNewStartdPid(t *testing.T, startdBin string, exclude []string, timeout time.Duration) string {
	t.Helper()
	old := map[string]bool{}
	for _, p := range exclude {
		old[p] = true
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, p := range pgrep(t, startdBin) {
			if !old[p] {
				return p
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return ""
}

// processAlive reports whether pid is a live process (signal 0).
func processAlive(pid int) bool {
	return exec.Command("kill", "-0", strconv.Itoa(pid)).Run() == nil
}

// waitForLogContains polls a log file until it contains substr.
func waitForLogContains(path, substr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil && strings.Contains(string(data), substr) {
			return true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false
}
