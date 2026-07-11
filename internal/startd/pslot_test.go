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
	shadow "github.com/bbockelm/golang-ap/shadow"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
	hstartd "github.com/bbockelm/golang-htcondor/startd"

	"github.com/bbockelm/golang-ep/internal/claim"
	"github.com/bbockelm/golang-ep/internal/persist"
	"github.com/bbockelm/golang-ep/internal/slot"
)

// pslotTotal is the machine size a test p-slot owns (4 cpus).
var pslotTotal = slot.Resources{Cpus: 4, MemoryMB: 4096, DiskKB: 400000}

// newTestPSlotCore builds a Core owning a single partitionable slot (4 cpus).
// storeDir != "" wires a durable claim store (for re-adoption tests).
func newTestPSlotCore(t *testing.T, sinful, storeDir string) (*Core, *security.SessionCache) {
	t.Helper()
	log, err := logging.New(nil)
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	cfg, err := config.NewFromReader(strings.NewReader("SLOT_TYPE_1_PARTITIONABLE=true\nSTART=TRUE\n"))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	slots := slot.BuildSlots(cfg, "testhost", sinful, pslotTotal, time.Now())
	if len(slots) != 1 || !slots[0].IsPartitionable() {
		t.Fatalf("expected one partitionable slot, got %d", len(slots))
	}
	cache := security.NewSessionCache()
	minter := claim.NewMinter(claim.MinterOptions{
		Cache:     cache,
		Sinful:    sinful,
		Birthdate: time.Now().Unix(),
	})
	opts := Options{
		Logger:                log,
		Slots:                 slots,
		Minter:                minter,
		SessionCache:          cache,
		AlivesMissed:          6,
		ExecuteDir:            t.TempDir(),
		StarterUpdateInterval: 200 * time.Millisecond,
		UIDDomain:             "example.net",
		FileSystemDomain:      "example.net",
		MaxVacateTime:         2 * time.Second,
	}
	if storeDir != "" {
		st, err := persist.Open(storeDir)
		if err != nil {
			t.Fatalf("persist.Open: %v", err)
		}
		t.Cleanup(func() { _ = st.Close() })
		opts.Store = st
	}
	return New(opts), cache
}

// startPSlotServer boots a p-slot Core + cedar server and returns the core plus
// a claim client bound to the p-slot's claim id.
func startPSlotServer(t *testing.T, ctx context.Context, storeDir string) (*Core, *hstartd.Client) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	sinful := fmt.Sprintf("<%s>", ln.Addr().String())

	core, cache := newTestPSlotCore(t, sinful, storeDir)
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

// liveSlotByName finds a slot in the core's live set by name.
func liveSlotByName(core *Core, name string) *slot.Slot {
	for _, s := range core.LiveSlots() {
		if s.Name == name {
			return s
		}
	}
	return nil
}

// pslotRequestAd builds a REQUEST_CLAIM request for a dslot with the given cpus.
func pslotRequestAd(cpus int) *classad.ClassAd {
	ad := classad.New()
	_ = ad.Set("User", "alice@example.net")
	_ = ad.Set("Owner", "alice")
	_ = ad.Set("ScheddName", "schedd@testhost")
	_ = ad.Set("RequestCpus", int64(cpus))
	_ = ad.Set("RequestMemory", int64(128))
	_ = ad.Set("RequestDisk", int64(1024))
	return ad
}

func requestDSlot(t *testing.T, ctx context.Context, sc *hstartd.Client, cpus int) *hstartd.ClaimResult {
	t.Helper()
	claimPSlot := true
	res, err := sc.RequestClaim(ctx, &hstartd.ClaimRequest{
		RequestAd:     pslotRequestAd(cpus),
		SchedulerAddr: "<127.0.0.1:1>",
		AliveInterval: 300, // slow: no ALIVE traffic during the test
		ClaimPSlot:    claimPSlot,
	})
	if err != nil {
		t.Fatalf("RequestClaim(cpus=%d): %v", cpus, err)
	}
	return res
}

// TestPSlotClaimCarvesDSlot: a REQUEST_CLAIM against the p-slot via the oracle
// client carves a dynamic slot, subtracts its resources, and replies with the
// dslot (code 7) + p-slot leftovers (code 5).
func TestPSlotClaimCarvesDSlot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	core, sc := startPSlotServer(t, ctx, "")

	res := requestDSlot(t, ctx, sc, 1)
	if !res.OK {
		t.Fatalf("p-slot claim not OK: %+v", res)
	}
	// The oracle client parsed a claimed slot (the dslot) ...
	if len(res.ClaimedSlots) != 1 {
		t.Fatalf("got %d claimed slots, want 1 (the dslot)", len(res.ClaimedSlots))
	}
	dAd := res.ClaimedSlots[0].SlotAd
	if v, _ := dAd.EvaluateAttrString("SlotType"); v != "Dynamic" {
		t.Errorf("claimed slot SlotType = %q, want Dynamic", v)
	}
	if v, _ := dAd.EvaluateAttrInt("Cpus"); v != 1 {
		t.Errorf("dslot Cpus = %d, want 1", v)
	}
	if v, _ := dAd.EvaluateAttrString("State"); v != "Claimed" {
		t.Errorf("dslot State = %q, want Claimed", v)
	}
	// ... and the p-slot leftovers with reduced resources.
	if !res.HasLeftovers {
		t.Fatal("no leftovers returned for the p-slot claim")
	}
	if res.Code != 5 { // SECURE_CLAIM_ID => code 5
		t.Errorf("leftovers code = %d, want 5 (REQUEST_CLAIM_LEFTOVERS_2)", res.Code)
	}
	if v, _ := res.LeftoverSlotAd.EvaluateAttrInt("Cpus"); v != 3 {
		t.Errorf("p-slot leftover Cpus = %d, want 3", v)
	}
	if v, _ := res.LeftoverSlotAd.EvaluateAttrBool("PartitionableSlot"); !v {
		t.Error("leftover ad missing PartitionableSlot")
	}

	// The live p-slot shows reduced resources + one child; a Dynamic slot appears.
	ps := core.Slots()[0]
	if got := ps.Resources().Cpus; got != 3 {
		t.Errorf("p-slot remaining Cpus = %d, want 3", got)
	}
	d := liveSlotByName(core, "slot1_1@testhost")
	if d == nil {
		t.Fatal("dynamic slot slot1_1@testhost not in the live set")
	}
	if d.State() != "Claimed" {
		t.Errorf("dslot state = %q, want Claimed", d.State())
	}
	priv := ps.PrivateAd()
	if v, _ := priv.EvaluateAttrInt("NumDynamicSlots"); v != 1 {
		t.Errorf("p-slot NumDynamicSlots = %d, want 1", v)
	}
	// The leftover claim id is the p-slot's OWN claim id (reused for more dslots).
	if res.LeftoverClaimID != ps.Claim().ClaimID() {
		t.Error("leftover claim id is not the p-slot's own claim id")
	}
}

// TestPSlotMultipleDSlotsAndExhaust: carve up to the p-slot's capacity, then
// reject an over-budget request.
func TestPSlotMultipleDSlotsAndExhaust(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	core, sc := startPSlotServer(t, ctx, "")
	ps := core.Slots()[0]

	// Carve two 1-cpu dslots and one 2-cpu dslot => 4 cpus total, p-slot exhausted.
	requestDSlot(t, ctx, sc, 1)
	requestDSlot(t, ctx, sc, 1)
	requestDSlot(t, ctx, sc, 2)
	if got := ps.Resources().Cpus; got != 0 {
		t.Fatalf("p-slot remaining Cpus = %d after carving all 4, want 0", got)
	}
	live := 0
	for _, s := range core.LiveSlots() {
		if s.IsDynamic() {
			live++
		}
	}
	if live != 3 {
		t.Errorf("live dslot count = %d, want 3", live)
	}
	// A further 1-cpu request is over budget (0 cpus remain) -> NOT_OK.
	res, err := sc.RequestClaim(ctx, &hstartd.ClaimRequest{
		RequestAd: pslotRequestAd(1), SchedulerAddr: "<127.0.0.1:1>", AliveInterval: 300, ClaimPSlot: true,
	})
	if err != nil {
		t.Fatalf("over-budget RequestClaim errored: %v", err)
	}
	if res.OK {
		t.Errorf("over-budget request was accepted: %+v", res)
	}
}

// TestPSlotReadopt: a carved dslot is reconstructed from the persisted store by
// a restarted startd, subtracting from the rebuilt p-slot.
func TestPSlotReadopt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	storeDir := t.TempDir()

	// First startd: carve a dslot, then stop (flushing the persister).
	func() {
		core, sc := startPSlotServer(t, ctx, storeDir)
		res := requestDSlot(t, ctx, sc, 1)
		if !res.OK {
			t.Fatalf("initial p-slot claim failed: %+v", res)
		}
		if liveSlotByName(core, "slot1_1@testhost") == nil {
			t.Fatal("dslot not carved before restart")
		}
		core.Stop() // drains the async persister to disk
	}()

	// Second startd: fresh cache + reopened store; re-adopt.
	core2, _ := newTestPSlotCore(t, "<127.0.0.1:12345>", storeDir)
	core2.Start(ctx)
	t.Cleanup(core2.Stop)
	core2.Adopt()

	d := liveSlotByName(core2, "slot1_1@testhost")
	if d == nil {
		t.Fatal("re-adoption did not reconstruct the dynamic slot")
	}
	if d.State() != "Claimed" {
		t.Errorf("re-adopted dslot state = %q, want Claimed", d.State())
	}
	if got := d.Resources().Cpus; got != 1 {
		t.Errorf("re-adopted dslot Cpus = %d, want 1", got)
	}
	ps := core2.Slots()[0]
	if got := ps.Resources().Cpus; got != 3 {
		t.Errorf("re-adopted p-slot remaining Cpus = %d, want 3 (carve replayed)", got)
	}
	priv := ps.PrivateAd()
	if v, _ := priv.EvaluateAttrInt("NumDynamicSlots"); v != 1 {
		t.Errorf("re-adopted p-slot NumDynamicSlots = %d, want 1", v)
	}
}

// TestDSlotActivateAndRelease: run a real job on a carved dslot, then RELEASE the
// dslot and confirm its resources return to the p-slot.
func TestDSlotActivateAndRelease(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	core, sc := startPSlotServer(t, ctx, "")
	ps := core.Slots()[0]

	res := requestDSlot(t, ctx, sc, 1)
	dslotClaimID := res.ClaimedSlots[0].ClaimID
	d := liveSlotByName(core, "slot1_1@testhost")
	if d == nil {
		t.Fatal("dslot not carved")
	}

	// Activate a short job on the dslot via a client bound to the dslot claim id.
	dsc, err := hstartd.New(dslotClaimID, nil)
	if err != nil {
		t.Fatalf("startd.New(dslot): %v", err)
	}
	jobAd := activateJobAd("/dev/null")
	_ = jobAd.Set("Arguments", "-c 'sleep 1; exit 0'")
	ac, err := dsc.ActivateClaim(ctx, jobAd, nil)
	if err != nil {
		t.Fatalf("ActivateClaim(dslot): %v", err)
	}
	sh, err := shadow.New(ac.Stream(), ac, shadow.Config{JobAd: jobAd, Logf: t.Logf})
	if err != nil {
		t.Fatalf("shadow.New: %v", err)
	}
	runCh := make(chan error, 1)
	go func() { _, e := sh.Run(ctx); runCh <- e }()

	waitSlotState(t, d, "Claimed", 5*time.Second)
	select {
	case <-runCh:
	case <-ctx.Done():
		t.Fatal("job never finished on the dslot")
	}
	// dslot returns to Claimed/Idle; p-slot still shows 3 cpus (dslot alive).
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && d.Activity() != "Idle" {
		time.Sleep(20 * time.Millisecond)
	}
	if d.Activity() != "Idle" {
		t.Fatalf("dslot activity after job = %q, want Idle", d.Activity())
	}
	if got := ps.Resources().Cpus; got != 3 {
		t.Errorf("p-slot Cpus while dslot idle = %d, want 3", got)
	}

	// RELEASE the dslot: it is destroyed and its cpu returns to the p-slot.
	if err := dsc.ReleaseClaim(ctx); err != nil {
		t.Fatalf("ReleaseClaim(dslot): %v", err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if liveSlotByName(core, "slot1_1@testhost") == nil && ps.Resources().Cpus == 4 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if liveSlotByName(core, "slot1_1@testhost") != nil {
		t.Error("dslot not destroyed after release")
	}
	if got := ps.Resources().Cpus; got != 4 {
		t.Errorf("p-slot Cpus after dslot release = %d, want 4 (restored)", got)
	}
	priv := ps.PrivateAd()
	if v, _ := priv.EvaluateAttrInt("NumDynamicSlots"); v != 0 {
		t.Errorf("p-slot NumDynamicSlots after release = %d, want 0", v)
	}
}
