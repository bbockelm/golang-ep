package integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	hstartd "github.com/bbockelm/golang-htcondor/startd"

	"github.com/bbockelm/golang-ap/shadow"
)

// TestStage8PSlot exercises partitionable slots + real vacate against the
// golang-ep startd (goroutine-mode starter) driven by golang-htcondor's startd
// claim client and golang-ap's embedded shadow:
//
//	(1) a REQUEST_CLAIM against the p-slot carves a dynamic slot -- the client
//	    parses a ClaimedSlot (the dslot, reduced resources) + a LeftoverSlotAd
//	    (the p-slot with remaining resources); the collector shows the p-slot
//	    with reduced Cpus + ChildClaimIds and a new Dynamic slot Claimed;
//	(2) a file-transfer job runs on the dslot to completion; releasing the dslot
//	    returns its resources to the p-slot (collector shows full Cpus, no
//	    children);
//	(3) two concurrent dslots subtract correctly and a third over-budget claim is
//	    refused NOT_OK;
//	(4) DEACTIVATE_CLAIM (soft) and DEACTIVATE_CLAIM_FORCIBLY vacate a running
//	    dslot job -- the response ad is returned, the starter is signaled and
//	    exits, and the dslot cleans up.
//
// Run in isolation: go test ./integration -run Stage8 (the box has leaked
// collectors; do NOT run the full ladder).
func TestStage8PSlot(t *testing.T) {
	for _, tool := range []string{"condor_master", "condor_status"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()
	startdBin := filepath.Join(tmp, fmt.Sprintf("golang-ep-startd-s8-%d", os.Getpid()))
	buildBin(t, startdBin, "../cmd/startd")

	executeDir := filepath.Join(tmp, "execute")
	if err := os.MkdirAll(executeDir, 0o755); err != nil {
		t.Fatalf("mkdir execute: %v", err)
	}

	const aliveInterval = 30 // long lease: no ALIVE fires during the fast test
	extra := fmt.Sprintf(`
DAEMON_LIST = MASTER, COLLECTOR, STARTD
STARTD = %s
STARTD_LOG = $(LOG)/StartdLog
STARTD_DEBUG = D_FULLDEBUG
STARTD_ADDRESS_FILE = $(LOG)/.startd_address

NUM_CPUS = 4
MEMORY = 2048
SLOT_TYPE_1_PARTITIONABLE = true
UPDATE_INTERVAL = 5
EXECUTE = %s
STARTER_UPDATE_INTERVAL = 2
KILLING_TIMEOUT = 5

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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	col := htcondor.NewCollector(h.GetCollectorAddr())

	if slots := waitForSlots(t, ctx, col, 1, 60*time.Second); len(slots) < 1 {
		dumpAllLogs()
		t.Fatal("p-slot never advertised")
	}
	// The advertised slot is the partitionable slot with 4 cpus.
	pslotClaimID, pslotName := waitForPrivateClaimID(t, ctx, h.GetCollectorAddr(), "", 45*time.Second)
	if pslotClaimID == "" {
		dumpAllLogs()
		t.Fatal("could not obtain the p-slot ClaimId")
	}
	if !waitForCollectorSlot(t, ctx, col, pslotName, 30*time.Second, func(ad *classad.ClassAd) string {
		if v, _ := ad.EvaluateAttrBool("PartitionableSlot"); !v {
			return "not PartitionableSlot"
		}
		if v, _ := ad.EvaluateAttrInt("Cpus"); v != 4 {
			return fmt.Sprintf("Cpus=%d", v)
		}
		return ""
	}) {
		dumpAllLogs()
		t.Fatalf("p-slot %s never advertised as Partitionable with 4 cpus", pslotName)
	}
	t.Logf("p-slot %s advertised (Partitionable, 4 cpus)", pslotName)

	whoami := "stage8user"
	if u, err := user.Current(); err == nil && u.Username != "" {
		whoami = u.Username
	}

	stub := newStubSchedd(t, pslotClaimID, aliveInterval)

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

	// psClient claims dslots out of the p-slot (its claim id is the leftover id,
	// reused for every dslot).
	psClient, err := hstartd.New(pslotClaimID, nil)
	if err != nil {
		t.Fatalf("startd.New(pslot): %v", err)
	}

	carve := func(reqAd *classad.ClassAd) *hstartd.ClaimResult {
		res, err := psClient.RequestClaim(ctx, &hstartd.ClaimRequest{
			RequestAd:     reqAd,
			SchedulerAddr: stub.addr,
			AliveInterval: aliveInterval,
			ScheddName:    "golang-ep-stage8@127.0.0.1",
			ClaimPSlot:    true,
		})
		if err != nil {
			dumpAllLogs()
			t.Fatalf("REQUEST_CLAIM(p-slot): %v", err)
		}
		return res
	}

	// =====================================================================
	// (1) + (2): carve a dslot, run an FT job on it, release, resources restored.
	// =====================================================================
	t.Run("CarveRunRelease", func(t *testing.T) {
		iwd, jobAd := stage4TransferJobAd(t, whoami, "hello-pslot", 3)
		_ = jobAd.Set("RequestCpus", int64(1))

		res := carve(jobAd)
		if !res.OK || len(res.ClaimedSlots) != 1 || !res.HasLeftovers {
			dumpAllLogs()
			t.Fatalf("p-slot claim reply unexpected: OK=%v claimed=%d leftovers=%v code=%d",
				res.OK, len(res.ClaimedSlots), res.HasLeftovers, res.Code)
		}
		dAd := res.ClaimedSlots[0].SlotAd
		dName, _ := dAd.EvaluateAttrString("Name")
		if v, _ := dAd.EvaluateAttrInt("Cpus"); v != 1 {
			t.Errorf("dslot Cpus = %d, want 1", v)
		}
		if v, _ := dAd.EvaluateAttrString("SlotType"); v != "Dynamic" {
			t.Errorf("claimed slot SlotType = %q, want Dynamic", v)
		}
		if v, _ := res.LeftoverSlotAd.EvaluateAttrInt("Cpus"); v != 3 {
			t.Errorf("p-slot leftover Cpus = %d, want 3", v)
		}
		t.Logf("carved dslot %s (leftover code %d); p-slot down to 3 cpus", dName, res.Code)
		dslotClaimID := res.ClaimedSlots[0].ClaimID

		// Collector: p-slot reduced to 3 cpus with 1 dynamic child; dslot Claimed.
		if !waitForCollectorSlot(t, ctx, col, pslotName, 30*time.Second, func(ad *classad.ClassAd) string {
			if v, _ := ad.EvaluateAttrInt("Cpus"); v != 3 {
				return fmt.Sprintf("pslot Cpus=%d", v)
			}
			if v, _ := ad.EvaluateAttrInt("NumDynamicSlots"); v != 1 {
				return fmt.Sprintf("NumDynamicSlots=%d", v)
			}
			return ""
		}) {
			dumpAllLogs()
			t.Fatal("collector never showed the p-slot reduced to 3 cpus + 1 child")
		}
		if !waitForCollectorSlot(t, ctx, col, dName, 30*time.Second, busyOrIdleClaimed) {
			dumpAllLogs()
			t.Fatalf("collector never showed dslot %s Claimed", dName)
		}
		// ChildClaimIds is in the p-slot PRIVATE ad.
		assertPSlotChildClaimIDs(t, ctx, h.GetCollectorAddr(), pslotName, 1)

		// Activate + run the FT job on the dslot.
		dsc, err := hstartd.New(dslotClaimID, nil)
		if err != nil {
			t.Fatalf("startd.New(dslot): %v", err)
		}
		ac, err := dsc.ActivateClaim(ctx, jobAd, nil)
		if err != nil {
			dumpAllLogs()
			t.Fatalf("ACTIVATE_CLAIM(dslot): %v", err)
		}
		sh, err := shadow.New(ac.Stream(), ac, shadow.Config{
			JobAd:            jobAd,
			ClaimID:          dslotClaimID,
			TransferEndpoint: endpoint,
			ShadowAddr:       stub.addr,
			Startd:           dsc,
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
		select {
		case r := <-runCh:
			if code, ok := r.ExitCode(); !ok || code != 0 {
				dumpAllLogs()
				t.Fatalf("dslot job exit code = %d (ok=%v), want 0", code, ok)
			}
		case e := <-errCh:
			dumpAllLogs()
			t.Fatalf("shadow.Run errored: %v", e)
		case <-ctx.Done():
			dumpAllLogs()
			t.Fatal("dslot job never completed")
		}
		got, err := os.ReadFile(filepath.Join(iwd, "result.txt"))
		if err != nil || string(got) != "RESULT:hello-pslot\n" {
			dumpAllLogs()
			t.Fatalf("result.txt = %q err=%v, want RESULT:hello-pslot", got, err)
		}
		t.Log("FT job ran on the dslot to completion with correct output")

		// dslot back to Claimed/Idle, then RELEASE -> resources restored to p-slot.
		if !waitForCollectorSlot(t, ctx, col, dName, 30*time.Second, idleCheck) {
			dumpAllLogs()
			t.Fatal("dslot never returned to Claimed/Idle")
		}
		if err := dsc.ReleaseClaim(ctx); err != nil {
			t.Fatalf("ReleaseClaim(dslot): %v", err)
		}
		if !waitForCollectorSlot(t, ctx, col, pslotName, 30*time.Second, func(ad *classad.ClassAd) string {
			if v, _ := ad.EvaluateAttrInt("Cpus"); v != 4 {
				return fmt.Sprintf("pslot Cpus=%d", v)
			}
			if v, _ := ad.EvaluateAttrInt("NumDynamicSlots"); v != 0 {
				return fmt.Sprintf("NumDynamicSlots=%d", v)
			}
			return ""
		}) {
			dumpAllLogs()
			t.Fatal("p-slot resources not restored to 4 cpus after dslot release")
		}
		t.Log("dslot released; p-slot restored to 4 cpus, no children")
	})

	// =====================================================================
	// (3): two concurrent dslots subtract correctly; a third over-budget refused.
	// =====================================================================
	t.Run("ConcurrentAndExhaust", func(t *testing.T) {
		ad2 := pslotClaimAd(whoami, 2)
		res2 := carve(ad2)
		if !res2.OK || len(res2.ClaimedSlots) != 1 {
			t.Fatalf("2-cpu carve failed: %+v", res2)
		}
		d2Name, _ := res2.ClaimedSlots[0].SlotAd.EvaluateAttrString("Name")
		d2Claim := res2.ClaimedSlots[0].ClaimID

		ad1 := pslotClaimAd(whoami, 1)
		res1 := carve(ad1)
		if !res1.OK || len(res1.ClaimedSlots) != 1 {
			t.Fatalf("1-cpu carve failed: %+v", res1)
		}
		d1Name, _ := res1.ClaimedSlots[0].SlotAd.EvaluateAttrString("Name")
		d1Claim := res1.ClaimedSlots[0].ClaimID
		if v, _ := res1.LeftoverSlotAd.EvaluateAttrInt("Cpus"); v != 1 {
			t.Errorf("p-slot leftover after 2+1 carve = %d cpus, want 1", v)
		}

		// Both dslots are Claimed; p-slot has 1 cpu + 2 children.
		if !waitForCollectorSlot(t, ctx, col, pslotName, 30*time.Second, func(ad *classad.ClassAd) string {
			if v, _ := ad.EvaluateAttrInt("Cpus"); v != 1 {
				return fmt.Sprintf("pslot Cpus=%d", v)
			}
			if v, _ := ad.EvaluateAttrInt("NumDynamicSlots"); v != 2 {
				return fmt.Sprintf("NumDynamicSlots=%d", v)
			}
			return ""
		}) {
			dumpAllLogs()
			t.Fatal("collector never showed p-slot at 1 cpu with 2 children")
		}

		// Over-budget: a 2-cpu request with only 1 cpu left -> NOT_OK.
		resBig, err := psClient.RequestClaim(ctx, &hstartd.ClaimRequest{
			RequestAd: pslotClaimAd(whoami, 2), SchedulerAddr: stub.addr, AliveInterval: aliveInterval, ClaimPSlot: true,
		})
		if err != nil {
			t.Fatalf("over-budget RequestClaim errored: %v", err)
		}
		if resBig.OK {
			t.Errorf("over-budget (2-cpu) claim accepted with 1 cpu left: %+v", resBig)
		}
		t.Logf("over-budget claim correctly refused (code %d)", resBig.Code)

		// Release both; p-slot restored to 4 cpus.
		for _, cid := range []string{d1Claim, d2Claim} {
			dc, err := hstartd.New(cid, nil)
			if err != nil {
				t.Fatalf("startd.New(dslot release): %v", err)
			}
			if err := dc.ReleaseClaim(ctx); err != nil {
				t.Fatalf("ReleaseClaim: %v", err)
			}
		}
		if !waitForCollectorSlot(t, ctx, col, pslotName, 30*time.Second, func(ad *classad.ClassAd) string {
			if v, _ := ad.EvaluateAttrInt("Cpus"); v != 4 {
				return fmt.Sprintf("pslot Cpus=%d", v)
			}
			return ""
		}) {
			dumpAllLogs()
			t.Fatal("p-slot not restored to 4 cpus after releasing both dslots")
		}
		t.Logf("two dslots %s + %s released; p-slot restored to 4 cpus", d1Name, d2Name)
	})

	// =====================================================================
	// (4): DEACTIVATE soft + forcibly vacate a running dslot job.
	// =====================================================================
	t.Run("Vacate", func(t *testing.T) {
		for _, variant := range []struct {
			name string
			dt   hstartd.DeactivateType
		}{
			{"soft", hstartd.DeactivateGraceful},
			{"forcibly", hstartd.DeactivateForcibly},
		} {
			t.Run(variant.name, func(t *testing.T) {
				jobAd := pslotSleepJobAd(whoami, 300)
				res := carve(jobAd)
				if !res.OK || len(res.ClaimedSlots) != 1 {
					t.Fatalf("carve for vacate failed: %+v", res)
				}
				dName, _ := res.ClaimedSlots[0].SlotAd.EvaluateAttrString("Name")
				dClaim := res.ClaimedSlots[0].ClaimID

				dsc, err := hstartd.New(dClaim, nil)
				if err != nil {
					t.Fatalf("startd.New(dslot): %v", err)
				}
				ac, err := dsc.ActivateClaim(ctx, jobAd, nil)
				if err != nil {
					dumpAllLogs()
					t.Fatalf("ACTIVATE_CLAIM(dslot): %v", err)
				}
				sh, err := shadow.New(ac.Stream(), ac, shadow.Config{
					JobAd:      jobAd,
					ClaimID:    dClaim,
					ShadowAddr: stub.addr,
					Startd:     dsc,
					KeepClaim:  true,
					Logf:       t.Logf,
				})
				if err != nil {
					dumpAllLogs()
					t.Fatalf("shadow.New: %v", err)
				}
				shDone := make(chan struct{})
				go func() { _, _ = sh.Run(ctx); close(shDone) }()

				if !waitForCollectorSlot(t, ctx, col, dName, 30*time.Second, busyCheck) {
					dumpAllLogs()
					t.Fatalf("dslot %s never went Claimed/Busy", dName)
				}

				// DEACTIVATE: assert the response ad, then the starter exits.
				respAd, err := dsc.DeactivateClaim(ctx, variant.dt)
				if err != nil {
					dumpAllLogs()
					t.Fatalf("DeactivateClaim(%s): %v", variant.name, err)
				}
				if v, ok := respAd.EvaluateAttrBool("Start"); !ok || !v {
					t.Errorf("%s deactivate reply Start = %v (ok=%v), want true", variant.name, v, ok)
				}

				// The job was signaled and exits; the dslot returns to Claimed/Idle.
				if !waitForCollectorSlot(t, ctx, col, dName, 30*time.Second, idleCheck) {
					dumpAllLogs()
					t.Fatalf("dslot %s never returned to Claimed/Idle after %s vacate", dName, variant.name)
				}
				select {
				case <-shDone:
				case <-time.After(20 * time.Second):
					t.Logf("shadow serve loop still running after %s vacate (job killed)", variant.name)
				}
				t.Logf("%s vacate: response ad returned, starter exited, dslot idle", variant.name)

				// Clean up: release the dslot, resources returned to the p-slot.
				if err := dsc.ReleaseClaim(ctx); err != nil {
					t.Fatalf("ReleaseClaim after %s vacate: %v", variant.name, err)
				}
				if !waitForCollectorSlot(t, ctx, col, pslotName, 30*time.Second, func(ad *classad.ClassAd) string {
					if v, _ := ad.EvaluateAttrInt("Cpus"); v != 4 {
						return fmt.Sprintf("pslot Cpus=%d", v)
					}
					return ""
				}) {
					dumpAllLogs()
					t.Fatalf("p-slot not restored to 4 cpus after %s vacate + release", variant.name)
				}
			})
		}
	})

	t.Log("Stage 8 OK: p-slot carve/leftovers/ChildClaimIds, dslot run+restore, concurrent+exhaust, soft/forcible vacate")
}

// busyOrIdleClaimed accepts a Claimed slot in either Busy or Idle activity.
func busyOrIdleClaimed(ad *classad.ClassAd) string {
	if v, _ := ad.EvaluateAttrString("State"); v != "Claimed" {
		return fmt.Sprintf("State=%q", v)
	}
	return ""
}

// pslotClaimAd builds a REQUEST_CLAIM request ad for a dslot with cpus cpus.
func pslotClaimAd(owner string, cpus int) *classad.ClassAd {
	ad := classad.New()
	_ = ad.Set("MyType", "Job")
	_ = ad.Set("Owner", owner)
	_ = ad.Set("User", owner+"@example.net")
	_ = ad.Set("JobUniverse", int64(5))
	_ = ad.Set("RequestCpus", int64(cpus))
	_ = ad.Set("RequestMemory", int64(128))
	_ = ad.Set("RequestDisk", int64(1024))
	_ = ad.Set("Requirements", true)
	return ad
}

// pslotSleepJobAd builds a runnable, no-file-transfer sleep job for the vacate
// cases (RequestCpus=1).
func pslotSleepJobAd(owner string, secs int) *classad.ClassAd {
	ad := pslotClaimAd(owner, 1)
	_ = ad.Set("Cmd", "/bin/sh")
	_ = ad.Set("Arguments", fmt.Sprintf("-c 'sleep %d'", secs))
	_ = ad.Set("Iwd", "/tmp")
	_ = ad.Set("In", "/dev/null")
	_ = ad.Set("Out", "/dev/null")
	_ = ad.Set("Err", "/dev/null")
	_ = ad.Set("ShouldTransferFiles", "NO")
	_ = ad.Set("GlobalJobId", fmt.Sprintf("golang-ep-stage8#1.0#%d", time.Now().UnixNano()))
	return ad
}

// assertPSlotChildClaimIDs queries the startd private ads and checks the p-slot's
// ChildClaimIds carries wantN entries.
func assertPSlotChildClaimIDs(t *testing.T, ctx context.Context, collectorAddr, pslotName string, wantN int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		ads, err := queryStartdPrivateAds(ctx, collectorAddr)
		if err == nil {
			for _, ad := range ads {
				if n, _ := ad.EvaluateAttrString("Name"); n != pslotName {
					continue
				}
				if v, ok := ad.EvaluateAttrInt("NumDynamicSlots"); ok && int(v) == wantN {
					if expr, ok := ad.Lookup("ChildClaimIds"); ok && expr != nil {
						t.Logf("p-slot private ad ChildClaimIds present (NumDynamicSlots=%d)", v)
						return
					}
				}
			}
		}
		time.Sleep(time.Second)
	}
	t.Errorf("p-slot %s private ad never showed ChildClaimIds with %d children", pslotName, wantN)
}
