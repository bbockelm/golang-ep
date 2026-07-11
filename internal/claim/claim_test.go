package claim

import (
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"
)

const testSinful = "<127.0.0.1:9618?sock=startd_test>"

func newTestMinter() (*Minter, *security.SessionCache) {
	cache := security.NewSessionCache()
	m := NewMinter(MinterOptions{
		Cache:     cache,
		Sinful:    testSinful,
		Birthdate: 1700000000,
	})
	return m, cache
}

// TestMintRoundTrip verifies a minted claim id parses back into the same
// session id via the strict C++-faithful parser, carries the startd sinful,
// and registers a resumable session in the shared cache.
func TestMintRoundTrip(t *testing.T) {
	m, cache := newTestMinter()
	cl, err := m.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	cid := cl.ClaimID()
	if !strings.HasPrefix(cid, testSinful+"#1700000000#") {
		t.Errorf("claim id %q does not start with <sinful>#birthdate#", cl.PublicClaimID())
	}

	parsed := security.ParseClaimIDStrict(cid)
	if parsed.SecSessionID() != cl.SessionID() {
		t.Errorf("parsed session id %q != minted session id %q", parsed.SecSessionID(), cl.SessionID())
	}
	if _, ok := cache.LookupNonExpired(cl.SessionID()); !ok {
		t.Error("minted session not present in the shared cache (inbound resumption would fail)")
	}

	// The public form must elide the secret.
	if strings.Contains(cl.PublicClaimID(), parsed.SecSessionKey()) {
		t.Error("public claim id leaks the secret key")
	}
}

// TestMintSequenceFresh verifies successive mints produce distinct claim ids and
// session ids (fresh sequence numbers).
func TestMintSequenceFresh(t *testing.T) {
	m, _ := newTestMinter()
	a, err := m.Mint()
	if err != nil {
		t.Fatalf("Mint a: %v", err)
	}
	b, err := m.Mint()
	if err != nil {
		t.Fatalf("Mint b: %v", err)
	}
	if a.ClaimID() == b.ClaimID() {
		t.Error("two mints produced the same claim id")
	}
	if a.SessionID() == b.SessionID() {
		t.Error("two mints produced the same session id")
	}
}

// TestAcceptTransition verifies the Unclaimed -> Claimed/Idle transition records
// the schedd identity and computes the lease deadline.
func TestAcceptTransition(t *testing.T) {
	m, _ := newTestMinter()
	cl, err := m.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if cl.State() != Unclaimed {
		t.Fatalf("fresh claim state = %v, want Unclaimed", cl.State())
	}

	now := time.Now()
	cl.Accept(AcceptInfo{
		ScheddAddr:    "<10.0.0.1:9618>",
		ScheddName:    "schedd@example",
		User:          "alice",
		ClientMachine: "10.0.0.1",
		AliveInterval: 10,
		AlivesMissed:  6,
		Now:           now,
	})

	if cl.State() != ClaimedIdle {
		t.Errorf("state after Accept = %v, want ClaimedIdle", cl.State())
	}
	if cl.State().StateName() != "Claimed" {
		t.Errorf("StateName = %q, want Claimed", cl.State().StateName())
	}
	if cl.ScheddAddr() != "<10.0.0.1:9618>" || cl.User() != "alice" || cl.ClientMachine() != "10.0.0.1" {
		t.Errorf("client info not recorded: addr=%q user=%q machine=%q", cl.ScheddAddr(), cl.User(), cl.ClientMachine())
	}
	wantDeadline := now.Add(60 * time.Second) // 6 * 10s
	if !cl.LeaseDeadline().Equal(wantDeadline) {
		t.Errorf("lease deadline = %v, want %v", cl.LeaseDeadline(), wantDeadline)
	}
	if cl.EnteredCurrentState() != now.Unix() {
		t.Errorf("EnteredCurrentState = %d, want %d", cl.EnteredCurrentState(), now.Unix())
	}
}

// TestExtendLease verifies a keepalive pushes the deadline forward.
func TestExtendLease(t *testing.T) {
	m, _ := newTestMinter()
	cl, _ := m.Mint()
	start := time.Now()
	cl.Accept(AcceptInfo{ScheddAddr: "<10.0.0.1:9618>", AliveInterval: 5, AlivesMissed: 6, Now: start})

	later := start.Add(20 * time.Second)
	cl.ExtendLease(6, later)
	want := later.Add(30 * time.Second)
	if !cl.LeaseDeadline().Equal(want) {
		t.Errorf("extended lease deadline = %v, want %v", cl.LeaseDeadline(), want)
	}
}

// TestLeaseMath pins the lease and ALIVE-cadence formulas: lease =
// alivesMissed*interval, cadence = lease/3 (2*interval at the default 6).
func TestLeaseMath(t *testing.T) {
	if d := LeaseDuration(10, 6); d != 60*time.Second {
		t.Errorf("LeaseDuration(10,6) = %v, want 60s", d)
	}
	if d := LeaseDuration(10, 0); d != 60*time.Second {
		t.Errorf("LeaseDuration(10,0) = %v, want 60s (default alives-missed)", d)
	}
	if d := AlivePeriod(10, 6); d != 20*time.Second {
		t.Errorf("AlivePeriod(10,6) = %v, want 20s (lease/3)", d)
	}
	if d := AlivePeriod(0, 0); d <= 0 {
		t.Errorf("AlivePeriod(0,0) = %v, want > 0", d)
	}
}

// TestMintRequiresCache guards the footgun of minting into a cache the server
// does not share.
func TestMintRequiresCache(t *testing.T) {
	m := NewMinter(MinterOptions{Sinful: testSinful})
	if _, err := m.Mint(); err == nil {
		t.Fatal("Mint with a nil cache should error")
	}
}
