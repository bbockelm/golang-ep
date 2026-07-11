package startd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	shadow "github.com/bbockelm/golang-ap/shadow"
	hstartd "github.com/bbockelm/golang-htcondor/startd"
)

// startCoreServer boots a Core + cedar server on a loopback listener and
// returns the core plus the first slot's claim client (the oracle proven
// against C++ startds).
func startCoreServer(t *testing.T, ctx context.Context, slots int) (*Core, *hstartd.Client) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	sinful := fmt.Sprintf("<%s>", ln.Addr().String())

	core, cache := newTestCore(t, slots, sinful)
	core.Start(ctx)
	t.Cleanup(core.Stop)

	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		SessionCache:   cache,
	})
	core.RegisterCommands(srv)
	go func() { _ = srv.Serve(ctx, ln) }()

	sc, err := hstartd.New(core.Slots()[0].Claim().ClaimID(), nil)
	if err != nil {
		t.Fatalf("startd.New: %v", err)
	}
	return core, sc
}

// claimSlot drives a REQUEST_CLAIM through the oracle client and waits for the
// slot to go Claimed.
func claimSlot(t *testing.T, ctx context.Context, core *Core, sc *hstartd.Client) {
	t.Helper()
	res, err := sc.RequestClaim(ctx, &hstartd.ClaimRequest{
		RequestAd:     fittingRequestAd(),
		SchedulerAddr: "<127.0.0.1:1>",
		AliveInterval: 300, // slow: no ALIVE traffic during the test
	})
	if err != nil || !res.OK {
		t.Fatalf("RequestClaim: err=%v res=%+v", err, res)
	}
	waitSlotState(t, core.Slots()[0], "Claimed", 5*time.Second)
}

// activateJobAd is a runnable vanilla job for the loopback happy path.
func activateJobAd(marker string) *classad.ClassAd {
	ad := fittingRequestAd()
	_ = ad.Set("JobUniverse", int64(5))
	_ = ad.Set("Cmd", "/bin/sh")
	_ = ad.Set("Arguments", fmt.Sprintf("-c 'printf stage3 > %s; exit 0'", marker))
	_ = ad.Set("Iwd", "/")
	_ = ad.Set("In", "/dev/null")
	_ = ad.Set("Out", "/dev/null")
	_ = ad.Set("Err", "/dev/null")
	_ = ad.Set("ShouldTransferFiles", "NO")
	return ad
}

// expectActivateNotOK asserts an ACTIVATE_CLAIM attempt is refused with
// NOT_OK (0).
func expectActivateNotOK(t *testing.T, ctx context.Context, sc *hstartd.Client, jobAd *classad.ClassAd, what string) {
	t.Helper()
	ac, err := sc.ActivateClaim(ctx, jobAd, &hstartd.ActivateOptions{MaxRetries: -1})
	if err == nil {
		_ = ac.Close()
		t.Fatalf("%s: ACTIVATE_CLAIM succeeded, want NOT_OK", what)
	}
	var fail *hstartd.ActivateFailure
	if !errors.As(err, &fail) {
		t.Fatalf("%s: err = %v, want *ActivateFailure", what, err)
	}
	if fail.Code != hstartd.ActivateNotOK {
		t.Fatalf("%s: reply code = %d, want NOT_OK(0)", what, fail.Code)
	}
}

// TestActivateClaimWire is the Stage-3 loopback oracle test: golang-htcondor's
// ActivateClaim client drives our ACTIVATE_CLAIM server end to end. The happy
// path keeps the activation socket, serves the starter's remote syscalls with
// the golang-ap shadow (the proven peer), and follows the slot through
// Claimed/Busy -> Claimed/Idle. Validation-path activations (wrong claim id /
// unclaimed slot / missing JobUniverse / requirements re-eval failure) are all
// refused NOT_OK without wedging the claim.
func TestActivateClaimWire(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	core, sc := startCoreServer(t, ctx, 2)
	s := core.Slots()[0]
	s2 := core.Slots()[1]

	// Reject: ACTIVATE on an UNCLAIMED slot (its pre-minted claim id resumes a
	// valid session, so the command reaches the handler).
	sc2, err := hstartd.New(s2.Claim().ClaimID(), nil)
	if err != nil {
		t.Fatalf("startd.New(slot2): %v", err)
	}
	expectActivateNotOK(t, ctx, sc2, activateJobAd("/dev/null"), "unclaimed slot")

	claimSlot(t, ctx, core, sc)

	// Reject: job ad without JobUniverse.
	noUniverse := activateJobAd("/dev/null")
	noUniverse.Delete("JobUniverse")
	expectActivateNotOK(t, ctx, sc, noUniverse, "missing JobUniverse")

	// Reject: requirements re-eval failure (asks for more cpus than the slot
	// has). This exercises the UNCLAIMED-form MatchAd path: the claimed slot
	// advertises Requirements=false, so a fitting job passing (below) plus a
	// non-fitting job failing proves the re-eval uses the reconstructed
	// expression, not the advertised literal.
	tooBig := activateJobAd("/dev/null")
	_ = tooBig.Set("RequestCpus", int64(1000))
	expectActivateNotOK(t, ctx, sc, tooBig, "requirements re-eval")

	// The rejects must not have wedged the slot.
	if s.State() != "Claimed" || s.Activity() != "Idle" {
		t.Fatalf("slot after rejected activations = %s/%s, want Claimed/Idle", s.State(), s.Activity())
	}

	// Happy path: activate, then serve the starter's syscalls with the
	// golang-ap shadow over the kept-open activation socket.
	marker := filepath.Join(t.TempDir(), "marker.txt")
	jobAd := activateJobAd(marker)
	_ = jobAd.Set("Arguments", fmt.Sprintf("-c 'sleep 1; printf stage3 > %s; exit 0'", marker))

	ac, err := sc.ActivateClaim(ctx, jobAd, nil)
	if err != nil {
		t.Fatalf("ActivateClaim: %v", err)
	}
	sh, err := shadow.New(ac.Stream(), ac, shadow.Config{
		JobAd: jobAd,
		Logf:  t.Logf,
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

	// While the job runs the slot is Claimed/Busy.
	busyDeadline := time.Now().Add(5 * time.Second)
	sawBusy := false
	for time.Now().Before(busyDeadline) {
		if s.State() == "Claimed" && s.Activity() == "Busy" {
			sawBusy = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !sawBusy {
		t.Errorf("slot never showed Claimed/Busy during the run (now %s/%s)", s.State(), s.Activity())
	}

	// Reject: a second ACTIVATE while Busy.
	expectActivateNotOK(t, ctx, sc, activateJobAd("/dev/null"), "already busy")

	var out runOut
	select {
	case out = <-runCh:
	case <-ctx.Done():
		t.Fatal("shadow.Run never returned")
	}
	if out.err != nil {
		t.Fatalf("shadow.Run: %v", out.err)
	}
	if code, ok := out.res.ExitCode(); !ok || code != 0 {
		t.Errorf("job exit code = %d (ok=%v), want 0", code, ok)
	}
	if !out.res.ExitedNormally() {
		t.Errorf("job exit reason = %d, want JOB_EXITED", out.res.Reason)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "stage3" {
		t.Errorf("marker file: data=%q err=%v, want \"stage3\"", data, err)
	}

	// After the starter exits the slot returns to Claimed/Idle (claim kept) and
	// the Final report is retained on the claim record.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if s.State() == "Claimed" && s.Activity() == "Idle" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if s.State() != "Claimed" || s.Activity() != "Idle" {
		t.Fatalf("slot after job = %s/%s, want Claimed/Idle", s.State(), s.Activity())
	}
	waitFinal := time.Now().Add(5 * time.Second)
	for time.Now().Before(waitFinal) {
		if ad, _, _ := s.Claim().Final(); ad != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	finalAd, status, reason := s.Claim().Final()
	if finalAd == nil {
		t.Error("claim record retained no Final ad")
	} else if status != 0 || reason != 100 {
		t.Errorf("claim Final status/reason = %d/%d, want 0/100", status, reason)
	}

	// RELEASE_CLAIM returns the slot to Unclaimed with a fresh claim id.
	oldID := s.Claim().ClaimID()
	if err := sc.ReleaseClaim(ctx); err != nil {
		t.Fatalf("ReleaseClaim: %v", err)
	}
	waitSlotState(t, s, "Unclaimed", 5*time.Second)
	if s.Claim().ClaimID() == oldID {
		t.Error("release did not mint a fresh claim id")
	}

	// Reject: the now-STALE claim id (session still cached) on ACTIVATE.
	expectActivateNotOK(t, ctx, sc, activateJobAd("/dev/null"), "stale claim id")
}

// TestReleaseWhileBusy: RELEASE_CLAIM on a Claimed/Busy slot kills the running
// starter (context cancel + best-effort VacateHard; provisional Stage-3
// semantics) and returns the slot to Unclaimed.
func TestReleaseWhileBusy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	core, sc := startCoreServer(t, ctx, 1)
	s := core.Slots()[0]
	claimSlot(t, ctx, core, sc)

	jobAd := activateJobAd("/dev/null")
	_ = jobAd.Set("Arguments", "-c 'sleep 300'")
	ac, err := sc.ActivateClaim(ctx, jobAd, nil)
	if err != nil {
		t.Fatalf("ActivateClaim: %v", err)
	}
	defer func() { _ = ac.Close() }()
	sh, err := shadow.New(ac.Stream(), ac, shadow.Config{JobAd: jobAd, Logf: t.Logf})
	if err != nil {
		t.Fatalf("shadow.New: %v", err)
	}
	runCh := make(chan error, 1)
	go func() {
		_, err := sh.Run(ctx)
		runCh <- err
	}()

	waitSlotState(t, s, "Claimed", 5*time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && s.Activity() != "Busy" {
		time.Sleep(10 * time.Millisecond)
	}
	if s.Activity() != "Busy" {
		t.Fatalf("slot never went Busy")
	}

	if err := sc.ReleaseClaim(ctx); err != nil {
		t.Fatalf("ReleaseClaim: %v", err)
	}
	waitSlotState(t, s, "Unclaimed", 10*time.Second)

	// The starter reports job_exit(JOB_KILLED) best-effort before winding
	// down, so the shadow's serve loop ends rather than hanging. Either a
	// killed-job result or a socket error is acceptable here -- the key
	// assertion is that it ENDS.
	select {
	case err := <-runCh:
		t.Logf("shadow.Run after release returned: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("shadow serve loop still running after release")
	}
}

// TestDeactivateStub: the DEACTIVATE_CLAIM variants read the wire and reply
// {Start: true} without killing anything (Stage-3 stub).
func TestDeactivateStub(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	core, sc := startCoreServer(t, ctx, 1)
	s := core.Slots()[0]
	claimSlot(t, ctx, core, sc)

	for _, dt := range []hstartd.DeactivateType{
		hstartd.DeactivateGraceful, hstartd.DeactivateForcibly,
		hstartd.DeactivateJobDone, hstartd.DeactivateFinalXfer,
	} {
		ad, err := sc.DeactivateClaim(ctx, dt)
		if err != nil {
			t.Fatalf("DeactivateClaim(%d): %v", dt, err)
		}
		if v, ok := ad.EvaluateAttrBool("Start"); !ok || !v {
			t.Errorf("DeactivateClaim(%d) reply Start = %v (ok=%v), want true", dt, v, ok)
		}
	}
	// Stub: the claim is untouched.
	if s.State() != "Claimed" {
		t.Errorf("slot after deactivate stubs = %s, want Claimed", s.State())
	}
}
