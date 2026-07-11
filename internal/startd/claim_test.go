package startd

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
	hstartd "github.com/bbockelm/golang-htcondor/startd"

	"github.com/bbockelm/golang-ep/internal/claim"
	"github.com/bbockelm/golang-ep/internal/slot"
)

// newTestCore builds a Core with n static slots, a Minter, and a shared session
// cache, without any advertiser (no collector in unit tests). sinful is the
// startd address embedded in the minted claim ids.
func newTestCore(t *testing.T, n int, sinful string) (*Core, *security.SessionCache) {
	t.Helper()
	log, err := logging.New(nil)
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	cfg, err := config.NewFromReader(strings.NewReader(fmt.Sprintf("NUM_SLOTS=%d\nSTART=TRUE\n", n)))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	total := slot.Resources{Cpus: n * 2, MemoryMB: int64(n) * 1024, DiskKB: int64(n) * 100000}
	slots := slot.BuildStaticSlots(cfg, "testhost", sinful, total, time.Now())

	cache := security.NewSessionCache()
	minter := claim.NewMinter(claim.MinterOptions{
		Cache:     cache,
		Sinful:    sinful,
		Birthdate: time.Now().Unix(),
	})
	core := New(Options{
		Logger:       log,
		Slots:        slots,
		Minter:       minter,
		SessionCache: cache,
		AlivesMissed: 6,
		// Stage 3: enable ACTIVATE_CLAIM with a per-test EXECUTE dir and a fast
		// starter-update cadence.
		ExecuteDir:            t.TempDir(),
		StarterUpdateInterval: 200 * time.Millisecond,
		UIDDomain:             "example.net",
		FileSystemDomain:      "example.net",
	})
	return core, cache
}

// fittingRequestAd builds a request/job ad that satisfies the slots'
// Requirements (START && WithinResourceLimits).
func fittingRequestAd() *classad.ClassAd {
	ad := classad.New()
	_ = ad.Set("User", "alice@example.net")
	_ = ad.Set("Owner", "alice")
	_ = ad.Set("ScheddName", "schedd@testhost")
	_ = ad.Set("RequestCpus", int64(1))
	_ = ad.Set("RequestMemory", int64(128))
	_ = ad.Set("RequestDisk", int64(1024))
	_ = ad.Set("_condor_SEND_CLAIMED_AD", true)
	return ad
}

// requestViaLoop submits an evRequestClaim to the running loop and returns the
// decision, failing the test on timeout.
func requestViaLoop(t *testing.T, c *Core, claimID string, reqAd *classad.ClassAd, scheddAddr string, aliveInterval int) claimDecision {
	t.Helper()
	reply := make(chan claimDecision, 1)
	c.Submit(evRequestClaim{
		claimID:       claimID,
		reqAd:         reqAd,
		scheddAddr:    scheddAddr,
		aliveInterval: aliveInterval,
		clientMachine: "127.0.0.1",
		reply:         reply,
	})
	select {
	case dec := <-reply:
		return dec
	case <-time.After(10 * time.Second):
		t.Fatal("event loop never answered the claim request")
		return claimDecision{}
	}
}

// waitSlotState polls a slot until it reports the wanted State.
func waitSlotState(t *testing.T, s *slot.Slot, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.State() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("slot %s state = %q, want %q", s.Name, s.State(), want)
}

// TestClaimStateMachine drives accept -> release through the event loop with no
// network: pre-minted claim, REQUEST accept, ad content while claimed, RELEASE
// re-mint, and the reject paths (bogus id, double claim, non-fitting job).
func TestClaimStateMachine(t *testing.T) {
	core, _ := newTestCore(t, 2, "<127.0.0.1:12345>")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	core.Start(ctx)
	defer core.Stop()

	s := core.Slots()[0]
	cl := s.Claim()
	if cl == nil {
		t.Fatal("slot has no pre-minted claim")
	}
	if got := s.State(); got != "Unclaimed" {
		t.Fatalf("initial state = %q, want Unclaimed", got)
	}

	// The private ad must carry the full secret claim id (the Stage-1 hook).
	priv := s.PrivateAd()
	if v, _ := priv.EvaluateAttrString("ClaimId"); v != cl.ClaimID() {
		t.Errorf("private ad ClaimId = %q, want the slot's full claim id", v)
	}
	if v, _ := priv.EvaluateAttrString("Capability"); v != cl.ClaimID() {
		t.Errorf("private ad Capability alias missing/wrong")
	}

	// Reject: bogus claim id.
	if dec := requestViaLoop(t, core, "bogus#1#2#nope", fittingRequestAd(), "<10.0.0.9:1>", 10); dec.accept {
		t.Fatal("bogus claim id was accepted")
	}

	// Reject: job that does not fit (too many cpus for one slot's share).
	tooBig := fittingRequestAd()
	_ = tooBig.Set("RequestCpus", int64(1000))
	if dec := requestViaLoop(t, core, cl.ClaimID(), tooBig, "<10.0.0.9:1>", 10); dec.accept {
		t.Fatal("non-fitting request was accepted")
	}
	if s.State() != "Unclaimed" {
		t.Fatalf("slot left Unclaimed by a rejected request: %q", s.State())
	}

	// Accept.
	dec := requestViaLoop(t, core, cl.ClaimID(), fittingRequestAd(), "<10.0.0.9:1>", 10)
	if !dec.accept {
		t.Fatal("valid claim request rejected")
	}
	if len(dec.claimedSlots) != 1 || dec.claimedSlots[0].ad == nil {
		t.Fatal("SEND_CLAIMED_AD did not produce a claimed slot ad")
	}
	if v, _ := dec.claimedSlots[0].ad.EvaluateAttrString("State"); v != "Claimed" {
		t.Errorf("claimed ad State = %q, want Claimed", v)
	}
	waitSlotState(t, s, "Claimed", 2*time.Second)

	// Claimed public-ad content: RemoteUser, ClientMachine, PublicClaimId, and
	// Requirements must be literally false so the slot never re-matches.
	pub := s.PublicAd()
	if v, _ := pub.EvaluateAttrString("RemoteUser"); v != "alice@example.net" {
		t.Errorf("RemoteUser = %q, want alice@example.net", v)
	}
	if v, _ := pub.EvaluateAttrString("ClientMachine"); v != "127.0.0.1" {
		t.Errorf("ClientMachine = %q", v)
	}
	if v, _ := pub.EvaluateAttrString("PublicClaimId"); v != cl.PublicClaimID() {
		t.Errorf("PublicClaimId = %q, want %q", v, cl.PublicClaimID())
	}
	if v, ok := pub.EvaluateAttrBool("Requirements"); !ok || v {
		t.Errorf("claimed Requirements = %v (ok=%v), want false", v, ok)
	}
	if cl.ScheddAddr() != "<10.0.0.9:1>" || cl.AliveInterval() != 10 {
		t.Errorf("claim lease info wrong: addr=%q interval=%d", cl.ScheddAddr(), cl.AliveInterval())
	}
	if cl.LeaseDeadline().Before(time.Now().Add(50 * time.Second)) {
		t.Errorf("lease deadline %v not ~60s out", cl.LeaseDeadline())
	}

	// Reject: the slot is no longer Unclaimed.
	if dec := requestViaLoop(t, core, cl.ClaimID(), fittingRequestAd(), "<10.0.0.9:1>", 10); dec.accept {
		t.Fatal("second claim on a Claimed slot was accepted")
	}

	// The second slot is independent and still Unclaimed.
	if got := core.Slots()[1].State(); got != "Unclaimed" {
		t.Errorf("slot2 state = %q, want Unclaimed", got)
	}

	// Release: back to Unclaimed with a FRESH claim id.
	oldID := cl.ClaimID()
	core.Submit(evReleaseClaim{claimID: oldID})
	waitSlotState(t, s, "Unclaimed", 2*time.Second)
	fresh := s.Claim()
	if fresh == nil || fresh.ClaimID() == oldID {
		t.Fatal("release did not mint a fresh claim id")
	}
	if fresh.State() != claim.Unclaimed {
		t.Errorf("fresh claim state = %v, want Unclaimed", fresh.State())
	}
	pub = s.PublicAd()
	if v, ok := pub.EvaluateAttrBool("Requirements"); ok && !v {
		t.Error("released slot still advertises Requirements=false")
	}
	if v, _ := pub.EvaluateAttrString("RemoteUser"); v != "" {
		t.Errorf("released slot still advertises RemoteUser=%q", v)
	}
}

// TestReleaseSlotEvent covers the ALIVE loop's release paths (schedd forgot the
// claim / lease expired): an evReleaseSlot must release the named slot.
func TestReleaseSlotEvent(t *testing.T) {
	core, _ := newTestCore(t, 1, "<127.0.0.1:12346>")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	core.Start(ctx)
	defer core.Stop()

	s := core.Slots()[0]
	oldID := s.Claim().ClaimID()
	dec := requestViaLoop(t, core, oldID, fittingRequestAd(), "<10.0.0.9:1>", 10)
	if !dec.accept {
		t.Fatal("claim request rejected")
	}
	waitSlotState(t, s, "Claimed", 2*time.Second)

	core.Submit(evReleaseSlot{slotName: s.Name, reason: "schedd forgot claim"})
	waitSlotState(t, s, "Unclaimed", 2*time.Second)
	if s.Claim().ClaimID() == oldID {
		t.Error("release did not mint a fresh claim id")
	}
}

// TestRequestClaimWire is the loopback oracle test: golang-htcondor's
// startd.Client (proven against C++ startds) drives our REQUEST_CLAIM /
// RELEASE_CLAIM servers over a real cedar connection, resuming the minted
// claim session.
func TestRequestClaimWire(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	sinful := fmt.Sprintf("<%s>", ln.Addr().String())

	core, cache := newTestCore(t, 1, sinful)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	core.Start(ctx)
	defer core.Stop()

	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		SessionCache:   cache, // MUST be the cache the Minter registered into
	})
	core.RegisterCommands(srv)
	go func() { _ = srv.Serve(ctx, ln) }()

	s := core.Slots()[0]
	claimID := s.Claim().ClaimID()

	// The oracle client: imports the claim session from the id, dials the
	// sinful at its head (our listener), and resumes the session.
	sc, err := hstartd.New(claimID, nil)
	if err != nil {
		t.Fatalf("startd.New: %v", err)
	}

	res, err := sc.RequestClaim(ctx, &hstartd.ClaimRequest{
		RequestAd:     fittingRequestAd(),
		SchedulerAddr: "<127.0.0.1:1>", // nobody home; ALIVE fires after the test
		AliveInterval: 10,
		ScheddName:    "wiretest@testhost",
	})
	if err != nil {
		t.Fatalf("RequestClaim: %v", err)
	}
	if !res.OK || res.Code != hstartd.ReplyOK {
		t.Fatalf("RequestClaim reply: ok=%v code=%d, want OK", res.OK, res.Code)
	}
	// The client sends _condor_SEND_CLAIMED_AD=true by default, so the claimed
	// slot ad must have arrived via the ReplySlotAd(7) loop.
	if len(res.ClaimedSlots) != 1 {
		t.Fatalf("ClaimedSlots = %d, want 1 (SEND_CLAIMED_AD)", len(res.ClaimedSlots))
	}
	if res.ClaimedSlots[0].ClaimID != claimID {
		t.Error("claimed-slot claim id does not round-trip")
	}
	if v, _ := res.ClaimedSlots[0].SlotAd.EvaluateAttrString("State"); v != "Claimed" {
		t.Errorf("claimed slot ad State = %q, want Claimed", v)
	}
	waitSlotState(t, s, "Claimed", 2*time.Second)

	// RELEASE_CLAIM (no reply on the wire) returns the slot to Unclaimed with a
	// fresh claim id.
	if err := sc.ReleaseClaim(ctx); err != nil {
		t.Fatalf("ReleaseClaim: %v", err)
	}
	waitSlotState(t, s, "Unclaimed", 5*time.Second)
	if s.Claim().ClaimID() == claimID {
		t.Error("release did not mint a fresh claim id")
	}

	// Negative: the STALE claim id (its session is still cached, so the client
	// can still connect and present it) must be rejected NOT_OK.
	res, err = sc.RequestClaim(ctx, &hstartd.ClaimRequest{
		RequestAd:     fittingRequestAd(),
		SchedulerAddr: "<127.0.0.1:1>",
		AliveInterval: 10,
	})
	if err != nil {
		t.Fatalf("RequestClaim (stale): %v", err)
	}
	if res.OK || res.Code != hstartd.ReplyNotOK {
		t.Fatalf("stale claim id: ok=%v code=%d, want NOT_OK", res.OK, res.Code)
	}
	if s.State() != "Unclaimed" {
		t.Errorf("slot state after rejected stale claim = %q, want Unclaimed", s.State())
	}
}
