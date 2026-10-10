package startd

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/golang-ep/internal/claim"
	"github.com/bbockelm/golang-ep/internal/persist"
)

// TestDoActivateClaim_JobAdNotSharedWithSupervisor drives an accepted
// ACTIVATE_CLAIM on a core with a claim store, so the job ad is rendered both
// for the starter's Activate message and for the persisted claim record. A
// ClassAd is not safe for concurrent use (rendering sorts its attributes and
// rebuilds its index in place), so only the loop may touch the job ad; when the
// supervisor goroutine rendered it as well, this test failed under -race.
func TestDoActivateClaim_JobAdNotSharedWithSupervisor(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	core, _ := newTestCore(t, 1, fmt.Sprintf("<%s>", ln.Addr().String()))

	store, err := persist.Open(t.TempDir())
	if err != nil {
		t.Fatalf("persist.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	core.store = store
	core.persister = newPersister(store, core.log)
	core.persister.start()
	persisterStopped := false
	t.Cleanup(func() {
		if !persisterStopped {
			core.persister.stop()
		}
	})

	// The loop is not running: this goroutine plays the loop.
	s := core.Slots()[0]
	now := time.Now()
	s.Claim().Accept(claim.AcceptInfo{
		ScheddAddr: "<127.0.0.1:1>", User: "alice@example.net",
		AliveInterval: 300, Now: now,
	})
	s.SetStateActivity("Claimed", "Idle", now)

	// A freshly parsed ad has not been sorted yet, as a job ad off the wire.
	src := activateJobAd("/dev/null")
	_ = src.Set("GlobalJobId", "submit.example.net#7.0#1")
	jobAd, err := classad.Parse(src.String())
	if err != nil {
		t.Fatalf("parse job ad: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reply := make(chan activateDecision, 1)
	core.doActivateClaim(ctx, evActivateClaim{claimID: s.Claim().ClaimID(), jobAd: jobAd, reply: reply})
	dec := <-reply
	if dec.code != activateOK {
		t.Fatalf("ACTIVATE_CLAIM decision = %d, want OK", dec.code)
	}
	if s.Activity() != "Busy" {
		t.Fatalf("slot activity = %s, want Busy", s.Activity())
	}

	// Tear the activation down and wait for the supervisor to report the
	// starter gone: by then it has sent (or failed to send) Activate.
	cancel()
	deadline := time.After(10 * time.Second)
	for exited := false; !exited; {
		select {
		case ev := <-core.events:
			if e, ok := ev.(evStarterExited); ok && e.slotName == s.Name {
				exited = true
			}
		case <-deadline:
			t.Fatal("supervisor never reported the starter exited")
		}
	}

	// The persisted claim record carries the activated job ad.
	core.persister.stop()
	persisterStopped = true
	rec, ok := store.Get(s.Name)
	if !ok {
		t.Fatal("no persisted claim record for the activated slot")
	}
	if rec.GlobalJobID != "submit.example.net#7.0#1" {
		t.Errorf("persisted GlobalJobID = %q", rec.GlobalJobID)
	}
	if !strings.Contains(rec.JobAd, "submit.example.net#7.0#1") {
		t.Errorf("persisted job ad lacks the job's GlobalJobId: %q", rec.JobAd)
	}
}
