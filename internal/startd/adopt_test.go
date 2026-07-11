package startd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"

	"github.com/bbockelm/golang-ep/internal/claim"
	"github.com/bbockelm/golang-ep/internal/persist"
	"github.com/bbockelm/golang-ep/internal/starter"
)

// mintTestClaim mints a real AES claim id (with a security session) so
// ImportClaimSession / ParseClaimIDStrict succeed during re-adoption.
func mintTestClaim(t *testing.T, cache *security.SessionCache, sinful string, seq int) (claimID, publicClaimID, sessionID string) {
	t.Helper()
	mc, err := security.MintClaimSession(cache, security.MintClaimOptions{
		Sinful:      sinful,
		Birthdate:   time.Now().Unix(),
		SequenceNum: seq,
	})
	if err != nil {
		t.Fatalf("MintClaimSession: %v", err)
	}
	return mc.ClaimID(), mc.PublicClaimID(), mc.SessionID()
}

func writeMarker(t *testing.T, sandbox string, status, reason int) {
	t.Helper()
	m := map[string]any{"waitpid_status": status, "reason": reason, "exit_time": time.Now().Unix()}
	data, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(sandbox, ".exit"), data, 0o600); err != nil {
		t.Fatalf("write .exit: %v", err)
	}
}

func adoptedBusyActivation(sandbox string) *activation {
	return &activation{
		cancel:    func() {},
		transport: starter.NewUnixStartd(filepath.Join(sandbox, "dead.sock")),
		vacateCh:  make(chan int, 1),
		sandbox:   sandbox,
		adopted:   true,
	}
}

// setBusyAdopted installs a Busy adopted claim on the core's first slot and
// records an activation, as re-adoption would before a redial is attempted.
func setBusyAdopted(t *testing.T, core *Core, cache *security.SessionCache, sandbox string) string {
	t.Helper()
	s := core.Slots()[0]
	claimID, pub, sid := mintTestClaim(t, cache, "<127.0.0.1:9618>", 1)
	s.SetClaim(claim.Adopt(claim.AdoptOptions{
		ClaimID: claimID, PublicClaimID: pub, SessionID: sid,
		ScheddAddr: "<127.0.0.1:1>", AliveInterval: 300, Busy: true,
		LeaseDeadline: time.Now().Add(30 * time.Minute), Entered: time.Now(),
	}))
	s.SetStateActivity("Claimed", "Busy", time.Now())
	core.activations[s.Name] = adoptedBusyActivation(sandbox)
	return s.Name
}

// TestReadExitMarker covers present / absent / corrupt markers.
func TestReadExitMarker(t *testing.T) {
	dir := t.TempDir()
	if _, ok := readExitMarker(dir); ok {
		t.Error("readExitMarker on empty sandbox should report absent")
	}
	writeMarker(t, dir, 0, 100)
	m, ok := readExitMarker(dir)
	if !ok || m.WaitpidStatus != 0 || m.Reason != 100 {
		t.Errorf("readExitMarker = %+v ok=%v, want status0/reason100", m, ok)
	}
	if err := os.WriteFile(filepath.Join(dir, ".exit"), []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := readExitMarker(dir); ok {
		t.Error("readExitMarker on corrupt marker should report absent")
	}
}

// TestAdoptFailed_ExitPresent: a surviving starter that finished during the
// downtime (a .exit marker exists) -> the recorded outcome is applied and the
// slot returns to Claimed/Idle (the claim survives).
func TestAdoptFailed_ExitPresent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	core, cache := newTestCore(t, 1, "<127.0.0.1:9618>")
	sandbox := t.TempDir()
	writeMarker(t, sandbox, 0, 100)
	slotName := setBusyAdopted(t, core, cache, sandbox)

	core.doAdoptFailed(ctx, slotName)

	s := core.Slots()[0]
	if s.State() != "Claimed" || s.Activity() != "Idle" {
		t.Fatalf("slot = %s/%s, want Claimed/Idle", s.State(), s.Activity())
	}
	if _, ok := core.activations[slotName]; ok {
		t.Error("activation not cleared after applying the terminal outcome")
	}
	if _, status, reason := s.Claim().Final(); status != 0 || reason != 100 {
		t.Errorf("recorded final = status%d/reason%d, want 0/100", status, reason)
	}
}

// TestAdoptFailed_NoMarker: a surviving starter that is simply gone (no marker)
// -> the claim is lost, released back to Unclaimed with a fresh id.
func TestAdoptFailed_NoMarker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	core, cache := newTestCore(t, 1, "<127.0.0.1:9618>")
	sandbox := t.TempDir() // no .exit written
	slotName := setBusyAdopted(t, core, cache, sandbox)
	oldClaim := core.Slots()[0].Claim().ClaimID()

	core.doAdoptFailed(ctx, slotName)

	s := core.Slots()[0]
	if s.State() != "Unclaimed" {
		t.Fatalf("slot = %s, want Unclaimed (claim lost)", s.State())
	}
	if _, ok := core.activations[slotName]; ok {
		t.Error("activation not cleared after declaring the claim lost")
	}
	if s.Claim().ClaimID() == oldClaim {
		t.Error("expected a fresh claim id after a lost claim was released")
	}
}

// TestDoAdopt_ReconstructsFromStore: doAdopt rebuilds a persisted Claimed/Idle
// claim -- re-registering its match session and marking the slot Claimed/Idle --
// without any starter redial.
func TestDoAdopt_ReconstructsFromStore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Build a core WITH a durable store seeded with one Claimed/Idle record.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { _ = ln.Close() })
	sinful := fmt.Sprintf("<%s>", ln.Addr().String())
	core, cache := newTestCore(t, 1, sinful)

	storeDir := t.TempDir()
	store, err := persist.Open(storeDir)
	if err != nil {
		t.Fatalf("persist.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	core.store = store

	slotName := core.Slots()[0].Name
	claimID, pub, _ := mintTestClaim(t, security.NewSessionCache(), sinful, 7)
	if err := store.Put(persist.Record{
		SlotName: slotName, ClaimID: claimID, PublicClaimID: pub,
		State: "Claimed", Activity: "Idle",
		ScheddAddr: "<127.0.0.1:1>", AliveInterval: 300,
		LeaseDeadline: time.Now().Add(30 * time.Minute).Unix(),
		Entered:       time.Now().Unix(),
	}); err != nil {
		t.Fatalf("store.Put: %v", err)
	}

	core.doAdopt(ctx)

	s := core.Slots()[0]
	if s.State() != "Claimed" || s.Activity() != "Idle" {
		t.Fatalf("adopted slot = %s/%s, want Claimed/Idle", s.State(), s.Activity())
	}
	if got := s.Claim().ClaimID(); got != claimID {
		t.Errorf("adopted claim id mismatch")
	}
	// The match session must be re-registered so inbound claim/CA commands resume.
	sid := security.ParseClaimIDStrict(claimID).SecSessionID()
	if _, ok := cache.LookupNonExpired(sid); !ok {
		t.Error("re-adoption did not re-register the claim's match session in the cache")
	}
	// Stop the ALIVE loop doAdopt started.
	if c := core.aliveCancels[slotName]; c != nil {
		c()
	}
}
