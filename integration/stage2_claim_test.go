package integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	htcondor "github.com/bbockelm/golang-htcondor"
	hstartd "github.com/bbockelm/golang-htcondor/startd"
)

// TestStage2Claim proves the Go startd's Stage-2 claim surface end to end
// against a real condor_master + C++ collector, with this test process acting
// as the schedd:
//
//	(1) harvest a slot's SECRET claim id from the collector's startd PRIVATE
//	    ads (QUERY_STARTD_PVT_ADS -- the negotiator path; this validates the
//	    private-ad ClaimId advertising, itself a Stage-2 deliverable);
//	(2) stand up a stub schedd (cedar server with the claim session imported
//	    and an ALIVE handler);
//	(3) REQUEST_CLAIM the slot via golang-htcondor's startd.Client (the oracle
//	    proven against C++ startds) -> OK, and the collector soon shows the
//	    slot Claimed/Idle with RemoteUser set and Requirements=False;
//	(4) the stub schedd receives >=2 session-resumed ALIVEs (lease loop);
//	(5) RELEASE_CLAIM -> collector shows Unclaimed again and the private ad
//	    carries a DIFFERENT (freshly minted) ClaimId;
//	(6) a stale claim id is rejected NOT_OK and the slot stays Unclaimed.
func TestStage2Claim(t *testing.T) {
	for _, tool := range []string{"condor_master", "condor_status"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found in PATH, skipping integration test", tool)
		}
	}

	tmp := t.TempDir()
	binName := fmt.Sprintf("golang-ep-startd-s2-%d", os.Getpid())
	startdBin := filepath.Join(tmp, binName)
	build := exec.Command("go", "build", "-buildvcs=false", "-o", startdBin, "../cmd/startd")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building golang-ep startd: %v\n%s", err, out)
	}

	const aliveInterval = 2 // seconds; ALIVE cadence = 6*2/3 = 4s
	const wantSlots = 2
	extra := fmt.Sprintf(`
DAEMON_LIST = MASTER, COLLECTOR, STARTD
STARTD = %s
STARTD_LOG = $(LOG)/StartdLog
STARTD_DEBUG = D_FULLDEBUG
STARTD_ADDRESS_FILE = $(LOG)/.startd_address

NUM_CPUS = 2
MEMORY = 512
NUM_SLOTS = %d
UPDATE_INTERVAL = 5

SEC_DEFAULT_AUTHENTICATION = REQUIRED
SEC_DEFAULT_AUTHENTICATION_METHODS = FS
SEC_CLIENT_AUTHENTICATION_METHODS = FS
SEC_DEFAULT_CRYPTO_METHODS = AES
`, startdBin, wantSlots)

	h := htcondor.SetupCondorHarnessWithConfig(t, extra)
	defer h.Shutdown()
	logDir := h.GetLogDir()

	// Point the in-process cedar client config at the harness so
	// NewClientSecurityConfig authenticates (FS) like a pool member -- needed
	// for the NEGOTIATOR-authorized private-ad query.
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

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	col := htcondor.NewCollector(h.GetCollectorAddr())

	// Wait for both slots to advertise.
	if slots := waitForSlots(t, ctx, col, wantSlots, 60*time.Second); len(slots) < wantSlots {
		dumpAllLogs()
		t.Fatalf("expected %d slot ads, got %d", wantSlots, len(slots))
	}

	// (1) Harvest a slot's claim id from the startd PRIVATE ads.
	claimID, slotName := waitForPrivateClaimID(t, ctx, h.GetCollectorAddr(), "", 45*time.Second)
	if claimID == "" {
		dumpAllLogs()
		t.Fatal("could not obtain a ClaimId from the startd private ads")
	}
	if security.ParseClaimIDStrict(claimID).SecSessionID() == "" {
		dumpAllLogs()
		t.Fatalf("claim id for %s carries no security session", slotName)
	}
	t.Logf("got claim id for slot %q (public %s)", slotName, security.ParseClaimIDStrict(claimID).PublicClaimID())

	// (2) Stub schedd: a cedar server with the claim session imported and an
	// ALIVE handler that records receipt and answers the interval.
	stub := newStubSchedd(t, claimID, aliveInterval)

	// (3) REQUEST_CLAIM via the oracle client.
	reqAd := classad.New()
	_ = reqAd.Set("User", "stage2user@example.net")
	_ = reqAd.Set("Owner", "stage2user")
	_ = reqAd.Set("RequestCpus", int64(1))
	_ = reqAd.Set("RequestMemory", int64(128))
	_ = reqAd.Set("RequestDisk", int64(1024))
	_ = reqAd.Set("JobUniverse", int64(5))

	sc, err := hstartd.New(claimID, nil)
	if err != nil {
		t.Fatalf("startd.New: %v", err)
	}
	res, err := sc.RequestClaim(ctx, &hstartd.ClaimRequest{
		RequestAd:     reqAd,
		SchedulerAddr: stub.addr,
		AliveInterval: aliveInterval,
		ScheddName:    "golang-ep-stage2@127.0.0.1",
	})
	if err != nil {
		dumpAllLogs()
		t.Fatalf("REQUEST_CLAIM: %v", err)
	}
	if !res.OK {
		dumpAllLogs()
		t.Fatalf("REQUEST_CLAIM rejected: code=%d", res.Code)
	}
	// The client requests SEND_CLAIMED_AD by default; the claimed ad must have
	// arrived and describe a Claimed slot.
	if len(res.ClaimedSlots) != 1 {
		dumpAllLogs()
		t.Fatalf("ClaimedSlots = %d, want 1", len(res.ClaimedSlots))
	}
	if v, _ := res.ClaimedSlots[0].SlotAd.EvaluateAttrString("State"); v != "Claimed" {
		t.Errorf("claimed slot ad State = %q, want Claimed", v)
	}
	t.Logf("REQUEST_CLAIM accepted (code=%d)", res.Code)

	// The collector must soon show the slot Claimed/Idle with RemoteUser and
	// Requirements=False (the startd re-advertises immediately on accept).
	if !waitForCollectorSlot(t, ctx, col, slotName, 30*time.Second, func(ad *classad.ClassAd) string {
		if v, _ := ad.EvaluateAttrString("State"); v != "Claimed" {
			return fmt.Sprintf("State=%q", v)
		}
		if v, _ := ad.EvaluateAttrString("Activity"); v != "Idle" {
			return fmt.Sprintf("Activity=%q", v)
		}
		if v, _ := ad.EvaluateAttrString("RemoteUser"); v != "stage2user@example.net" {
			return fmt.Sprintf("RemoteUser=%q", v)
		}
		if v, ok := ad.EvaluateAttrBool("Requirements"); !ok || v {
			return fmt.Sprintf("Requirements=%v (ok=%v), want false", v, ok)
		}
		return ""
	}) {
		dumpAllLogs()
		t.Fatalf("collector never showed %s Claimed/Idle with RemoteUser + Requirements=False", slotName)
	}
	t.Logf("collector shows %s Claimed/Idle, RemoteUser set, Requirements=False", slotName)

	// (4) The stub schedd must receive >=2 ALIVEs. Cadence is lease/3 =
	// (6*aliveInterval)/3 = 2*aliveInterval = 4s, so allow ~3 periods.
	if !stub.waitForAlives(2, time.Duration(3*3*aliveInterval)*time.Second) {
		dumpAllLogs()
		t.Fatalf("stub schedd received %d ALIVEs, want >= 2", stub.aliveCount())
	}
	for i, ev := range stub.events() {
		if !ev.resumed {
			t.Errorf("ALIVE %d was not session-resumed (fresh handshake)", i)
		}
		if !ev.encrypted {
			t.Errorf("ALIVE %d stream not encrypted", i)
		}
		if ev.claimID != claimID {
			t.Errorf("ALIVE %d carried the wrong claim id", i)
		}
	}
	t.Logf("stub schedd received %d session-resumed ALIVEs", stub.aliveCount())

	// (5) RELEASE_CLAIM -> Unclaimed with a fresh ClaimId in the private ad.
	if err := sc.ReleaseClaim(ctx); err != nil {
		dumpAllLogs()
		t.Fatalf("RELEASE_CLAIM: %v", err)
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
	newClaimID, _ := waitForFreshClaimID(t, ctx, h.GetCollectorAddr(), slotName, claimID, 30*time.Second)
	if newClaimID == "" {
		dumpAllLogs()
		t.Fatalf("private ad for %s never advertised a fresh ClaimId after release", slotName)
	}
	t.Logf("release re-minted the claim id (public %s)", security.ParseClaimIDStrict(newClaimID).PublicClaimID())

	// (6) Negative: the STALE claim id (the old session is still cached
	// server-side, so the command connects, but no slot matches the id) must be
	// rejected NOT_OK. A fully fabricated claim id is rejected even earlier, at
	// session resumption, and never reaches the claim handler.
	res, err = sc.RequestClaim(ctx, &hstartd.ClaimRequest{
		RequestAd:     reqAd,
		SchedulerAddr: stub.addr,
		AliveInterval: aliveInterval,
	})
	if err != nil {
		dumpAllLogs()
		t.Fatalf("REQUEST_CLAIM (stale id): %v", err)
	}
	if res.OK || res.Code != hstartd.ReplyNotOK {
		dumpAllLogs()
		t.Fatalf("stale claim id: ok=%v code=%d, want NOT_OK", res.OK, res.Code)
	}
	if !waitForCollectorSlot(t, ctx, col, slotName, 15*time.Second, func(ad *classad.ClassAd) string {
		if v, _ := ad.EvaluateAttrString("State"); v != "Unclaimed" {
			return fmt.Sprintf("State=%q", v)
		}
		return ""
	}) {
		t.Fatalf("slot %s left Unclaimed by the rejected stale claim", slotName)
	}
	t.Log("Stage 2 OK: private-ad claim id, claim, alives, release + re-mint, stale-claim reject")
}

// --- stub schedd ---

// stubAliveEvent records one ALIVE received by the stub schedd.
type stubAliveEvent struct {
	claimID   string
	resumed   bool
	encrypted bool
}

// stubSchedd is the in-test schedd: a cedar server whose cache holds the claim
// session (imported exactly as golang-ap's match table does) and whose ALIVE
// handler records receipts and answers the interval.
type stubSchedd struct {
	addr string // schedd command sinful "<host:port>"

	mu  sync.Mutex
	evs []stubAliveEvent
}

func newStubSchedd(t *testing.T, claimID string, aliveInterval int) *stubSchedd {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("stub schedd listen: %v", err)
	}
	addr := fmt.Sprintf("<%s>", ln.Addr().String())

	// Import the claim session with the submit-side identity: the schedd is the
	// submit side of a claim, matching what the startd's mint registered.
	cache := security.NewSessionCache()
	if _, err := security.ImportClaimSession(cache, claimID, security.ClaimSessionOptions{
		PeerAddr:           addr,
		PeerFQU:            security.SubmitSideMatchSessionFQU,
		ExtraValidCommands: []int{int(commands.ALIVE)},
	}); err != nil {
		t.Fatalf("stub schedd ImportClaimSession: %v", err)
	}

	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		SessionCache:   cache,
	})

	s := &stubSchedd{addr: addr}
	srv.Handle(int(commands.ALIVE), func(ctx context.Context, c *cedarserver.Conn) error {
		in := message.NewMessageFromStream(c.Stream)
		cid, err := in.GetString(ctx)
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.evs = append(s.evs, stubAliveEvent{
			claimID:   cid,
			resumed:   c.Negotiation != nil && c.Negotiation.SessionResumed,
			encrypted: c.Stream.IsEncrypted(),
		})
		s.mu.Unlock()
		out := message.NewMessageForStream(c.Stream)
		if err := out.PutInt(ctx, aliveInterval); err != nil {
			return err
		}
		return out.FinishMessage(ctx)
	}, "READ")

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	return s
}

func (s *stubSchedd) aliveCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.evs)
}

func (s *stubSchedd) events() []stubAliveEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]stubAliveEvent, len(s.evs))
	copy(out, s.evs)
	return out
}

func (s *stubSchedd) waitForAlives(n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.aliveCount() >= n {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return s.aliveCount() >= n
}

// --- private-ad (claim id) queries ---

// queryStartdPrivateAds runs QUERY_STARTD_PVT_ADS (10) against the collector
// and returns the startd private ads, which carry the slots' secret claim ids.
// The C++ collector authorizes this at NEGOTIATOR; the harness user (FS auth)
// is allowed everything. Same wire as golang-ap's stage2 test.
func queryStartdPrivateAds(ctx context.Context, collectorAddr string) ([]*classad.ClassAd, error) {
	sec, err := htcondor.NewClientSecurityConfig(ctx, "", collectorAddr, int(commands.QUERY_STARTD_PVT_ADS), "CLIENT", nil)
	if err != nil {
		return nil, fmt.Errorf("building security config: %w", err)
	}
	hc, err := client.ConnectAndAuthenticate(ctx, collectorAddr, sec)
	if err != nil {
		return nil, fmt.Errorf("connect/auth to collector: %w", err)
	}
	defer func() { _ = hc.Close() }()
	st := hc.GetStream()

	q := classad.New()
	_ = q.Set("MyType", "Query")
	_ = q.Set("TargetType", "Machine")
	_ = q.Set("Requirements", true)
	out := message.NewMessageForStream(st)
	if err := out.PutClassAd(ctx, q); err != nil {
		return nil, err
	}
	if err := out.FinishMessage(ctx); err != nil {
		return nil, err
	}

	in := message.NewMessageFromStream(st)
	var ads []*classad.ClassAd
	for {
		more, err := in.GetInt(ctx)
		if err != nil {
			return ads, fmt.Errorf("reading 'more' flag: %w", err)
		}
		if more == 0 {
			break
		}
		ad, err := in.GetClassAd(ctx)
		if err != nil {
			return ads, fmt.Errorf("reading pvt ad: %w", err)
		}
		ads = append(ads, ad)
	}
	return ads, nil
}

// waitForPrivateClaimID polls the private ads until one carrying a ClaimId (or
// Capability) appears -- for slotName if non-empty, else any slot -- returning
// (claimID, slotName).
func waitForPrivateClaimID(t *testing.T, ctx context.Context, collectorAddr, slotName string, timeout time.Duration) (string, string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ads, err := queryStartdPrivateAds(ctx, collectorAddr)
		if err != nil {
			t.Logf("pvt-ad query error (will retry): %v", err)
			time.Sleep(time.Second)
			continue
		}
		for _, ad := range ads {
			name, _ := ad.EvaluateAttrString("Name")
			if slotName != "" && name != slotName {
				continue
			}
			cid, _ := ad.EvaluateAttrString("ClaimId")
			if cid == "" {
				cid, _ = ad.EvaluateAttrString("Capability")
			}
			if cid != "" {
				return cid, name
			}
		}
		time.Sleep(time.Second)
	}
	return "", ""
}

// waitForFreshClaimID polls until slotName's private ad advertises a ClaimId
// different from oldClaimID (the post-release re-mint).
func waitForFreshClaimID(t *testing.T, ctx context.Context, collectorAddr, slotName, oldClaimID string, timeout time.Duration) (string, string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		cid, name := waitForPrivateClaimID(t, ctx, collectorAddr, slotName, 2*time.Second)
		if cid != "" && cid != oldClaimID {
			return cid, name
		}
		time.Sleep(time.Second)
	}
	return "", ""
}

// waitForCollectorSlot polls the collector's Machine ads for slotName until
// check returns "" (satisfied) or the timeout elapses. check returns a
// human-readable mismatch for logging.
func waitForCollectorSlot(t *testing.T, ctx context.Context, col *htcondor.Collector, slotName string, timeout time.Duration, check func(*classad.ClassAd) string) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	lastMismatch := "(no ad seen)"
	for time.Now().Before(deadline) {
		ads := querySlots(ctx, col)
		if ad, ok := ads[slotName]; ok {
			if mismatch := check(ad); mismatch == "" {
				return true
			} else {
				lastMismatch = mismatch
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Logf("slot %s last mismatch: %s", slotName, lastMismatch)
	return false
}
