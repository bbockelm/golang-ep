package startd

import (
	"context"
	"testing"
	"time"

	shadow "github.com/bbockelm/golang-ap/shadow"
	hstartd "github.com/bbockelm/golang-htcondor/startd"

	"github.com/bbockelm/golang-ep/internal/starter"
)

// activateLongJob claims + activates a long-running job on the core's slot0 and
// returns the running shadow's result channel.
func activateLongJob(t *testing.T, ctx context.Context, core *Core, sc *hstartd.Client, args string) chan error {
	t.Helper()
	claimSlot(t, ctx, core, sc)
	s := core.Slots()[0]
	jobAd := activateJobAd("/dev/null")
	_ = jobAd.Set("Arguments", args)
	ac, err := sc.ActivateClaim(ctx, jobAd, nil)
	if err != nil {
		t.Fatalf("ActivateClaim: %v", err)
	}
	sh, err := shadow.New(ac.Stream(), ac, shadow.Config{JobAd: jobAd, Logf: t.Logf})
	if err != nil {
		t.Fatalf("shadow.New: %v", err)
	}
	runCh := make(chan error, 1)
	go func() { _, e := sh.Run(ctx); runCh <- e }()
	// Wait for Claimed/Busy.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if s.State() == "Claimed" && s.Activity() == "Busy" {
			return runCh
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("slot never went Claimed/Busy")
	return runCh
}

func waitActivity(t *testing.T, core *Core, want string, timeout time.Duration) {
	t.Helper()
	s := core.Slots()[0]
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.Activity() == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("slot activity = %q, want %q", s.Activity(), want)
}

// TestDeactivateSoftVacate: DEACTIVATE_CLAIM (403) replies {Start:true} and then
// SIGTERMs the job's process group; the (killable) job exits and the slot
// returns to Claimed/Idle.
func TestDeactivateSoftVacate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	core, sc := startCoreServer(t, ctx, 1)
	runCh := activateLongJob(t, ctx, core, sc, "-c 'sleep 300'")

	ad, err := sc.DeactivateClaim(ctx, hstartd.DeactivateGraceful)
	if err != nil {
		t.Fatalf("DeactivateClaim(graceful): %v", err)
	}
	if v, ok := ad.EvaluateAttrBool("Start"); !ok || !v {
		t.Errorf("soft-deactivate reply Start = %v (ok=%v), want true (claim not closing)", v, ok)
	}
	// The starter was SIGTERMed and exits; slot returns to Claimed/Idle.
	waitActivity(t, core, "Idle", 20*time.Second)
	select {
	case <-runCh:
	case <-time.After(20 * time.Second):
		t.Fatal("shadow.Run did not end after soft vacate")
	}
	if core.Slots()[0].State() != "Claimed" {
		t.Errorf("slot state after soft vacate = %q, want Claimed (reusable)", core.Slots()[0].State())
	}
}

// TestDeactivateForcibly: DEACTIVATE_CLAIM_FORCIBLY (404) replies then SIGKILLs
// the job immediately.
func TestDeactivateForcibly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	core, sc := startCoreServer(t, ctx, 1)
	runCh := activateLongJob(t, ctx, core, sc, "-c 'sleep 300'")

	ad, err := sc.DeactivateClaim(ctx, hstartd.DeactivateForcibly)
	if err != nil {
		t.Fatalf("DeactivateClaim(forcibly): %v", err)
	}
	if v, ok := ad.EvaluateAttrBool("Start"); !ok || !v {
		t.Errorf("forcible-deactivate reply Start = %v (ok=%v), want true", v, ok)
	}
	waitActivity(t, core, "Idle", 20*time.Second)
	select {
	case <-runCh:
	case <-time.After(20 * time.Second):
		t.Fatal("shadow.Run did not end after forcible vacate")
	}
}

// TestDeactivateJobDone413: DEACTIVATE_CLAIM_JOB_DONE (413) does NOT kill the
// starter; if it is still running the reply is stashed and sent only after the
// starter reaps. The job runs to normal completion (not killed).
func TestDeactivateJobDone413(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	core, sc := startCoreServer(t, ctx, 1)
	// A short job so the 413 (issued while it runs) blocks until it reaps ~2s later.
	runCh := activateLongJob(t, ctx, core, sc, "-c 'sleep 2; exit 0'")

	start := time.Now()
	ad, err := sc.DeactivateClaim(ctx, hstartd.DeactivateJobDone)
	if err != nil {
		t.Fatalf("DeactivateClaim(jobdone): %v", err)
	}
	if v, ok := ad.EvaluateAttrBool("Start"); !ok || !v {
		t.Errorf("job-done reply Start = %v (ok=%v), want true", v, ok)
	}
	t.Logf("413 reply returned after %s (deferred until reap)", time.Since(start))

	// The job was NOT killed by the 413: it completed normally.
	select {
	case e := <-runCh:
		if e != nil {
			t.Logf("shadow.Run returned %v", e)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("job never completed after 413")
	}
	waitActivity(t, core, "Idle", 10*time.Second)
}

// TestVacateSoftEscalation drives doVacate/doVacateEscalate directly (no live
// loop): a soft vacate emits MsgVacateSoft immediately and, after maxVacateTime,
// submits an escalation event whose handling emits MsgVacateHard.
func TestVacateSoftEscalation(t *testing.T) {
	core, _ := newTestCore(t, 1, "<127.0.0.1:1>")
	core.maxVacateTime = 150 * time.Millisecond
	slotName := core.Slots()[0].Name
	act := &activation{vacateCh: make(chan int, 4), gen: 7, cancel: func() {}}
	core.activations[slotName] = act

	core.doVacate(context.Background(), evVacate{slotName: slotName, hard: false})

	// Immediate soft signal.
	select {
	case m := <-act.vacateCh:
		if m != starter.MsgVacateSoft {
			t.Fatalf("first vacate msg = %d, want MsgVacateSoft", m)
		}
	case <-time.After(time.Second):
		t.Fatal("soft vacate never emitted MsgVacateSoft")
	}

	// The escalation timer submits evVacateEscalate after maxVacateTime.
	select {
	case ev := <-core.events:
		esc, ok := ev.(evVacateEscalate)
		if !ok {
			t.Fatalf("escalation submitted %T, want evVacateEscalate", ev)
		}
		if esc.gen != act.gen {
			t.Fatalf("escalation gen = %d, want %d", esc.gen, act.gen)
		}
		core.doVacateEscalate(esc)
	case <-time.After(2 * time.Second):
		t.Fatal("soft vacate never escalated (no evVacateEscalate)")
	}

	// Escalation emits a hard kill.
	select {
	case m := <-act.vacateCh:
		if m != starter.MsgVacateHard {
			t.Fatalf("escalation msg = %d, want MsgVacateHard", m)
		}
	case <-time.After(time.Second):
		t.Fatal("escalation did not emit MsgVacateHard")
	}

	// A stale escalation (wrong gen) is a no-op.
	core.doVacateEscalate(evVacateEscalate{slotName: slotName, gen: 999})
	select {
	case m := <-act.vacateCh:
		t.Fatalf("stale escalation emitted a message %d, want none", m)
	default:
	}
}
