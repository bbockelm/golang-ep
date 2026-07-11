// Package startd implements the EP's single-writer core: one goroutine owns all
// mutable startd state (the slot claim state machine and the advertise timing),
// mirroring golang-ap/internal/sched in miniature. Command handlers, the ALIVE
// lease goroutines, and timers feed the loop via Submit(Event) rather than
// touching state directly; the slots themselves carry a small mutex only so the
// query/advertise paths can safely READ concurrently with the loop's writes.
//
// Command surface (registered on the shared cedar server):
//   - QUERY_STARTD_ADS (5): the collector-style query wire condor_status -direct
//     and the negotiator speak -- getClassAd(query)+EOM then, per matching slot,
//     PutInt(1)+putClassAd(public ad), terminated by PutInt(0)+EOM.
//   - GIVE_STATE (448): put the machine's state string.
//   - REQUEST_CLAIM (442) / RELEASE_CLAIM (443): the claim surface (claim.go),
//     riding the claim-id-derived match sessions minted into the shared
//     SessionCache.
package startd

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/collections/vm"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/golang-htcondor/logging"

	"github.com/bbockelm/golang-ep/internal/advertise"
	"github.com/bbockelm/golang-ep/internal/claim"
	"github.com/bbockelm/golang-ep/internal/persist"
	"github.com/bbockelm/golang-ep/internal/reconnect"
	"github.com/bbockelm/golang-ep/internal/slot"
)

// Event is a unit of work delivered to the core's event loop.
type Event interface{ isEvent() }

// evReschedule requests an immediate advertise (unused in Stage 1's command
// surface but present so the loop's fan-in pattern is established).
type evReschedule struct{}

func (evReschedule) isEvent() {}

// Options configures a Core.
type Options struct {
	Logger *logging.Logger
	// Slots is the slot set the core owns, advertises, and serves queries from.
	Slots []*slot.Slot
	// Advertiser pushes the slots' public+private ad pairs and invalidates them
	// on shutdown.
	Advertiser *advertise.Advertiser
	// UpdateInterval is how often the slots are re-advertised (UPDATE_INTERVAL).
	UpdateInterval time.Duration
	// Minter mints each slot's claim id (pre-minted at construction, re-minted
	// on release). Nil disables claiming (Stage-1-only cores / some unit tests).
	Minter *claim.Minter
	// SessionCache is the shared cache the startd's cedar server resumes claim
	// sessions from AND the ALIVE loop resumes the schedd session from. It MUST
	// be the same cache the Minter registers into and the cedar server was built
	// with.
	SessionCache *security.SessionCache
	// AlivesMissed is MAX_CLAIM_ALIVES_MISSED (default 6): lease =
	// AlivesMissed * alive_interval, ALIVE cadence = lease/3.
	AlivesMissed int
	// MatchTimeout is MATCH_TIMEOUT (default 120s): how long a slot stays in
	// Matched state awaiting a REQUEST_CLAIM before returning to Unclaimed with a
	// freshly minted (the matched id is invalidated) claim.
	MatchTimeout time.Duration
	// ExecuteDir is the EXECUTE directory job sandboxes are created under.
	// Empty rejects every ACTIVATE_CLAIM (Stage-1/2 cores).
	ExecuteDir string
	// StarterUpdateInterval is the spawned starters' periodic-update cadence
	// (STARTER_UPDATE_INTERVAL; <=0 uses the starter's 300s default).
	StarterUpdateInterval time.Duration
	// UIDDomain / FileSystemDomain seed the starters' register_starter_info ad.
	UIDDomain        string
	FileSystemDomain string

	// StarterMode selects how starters run: "goroutine" (default; in-process) or
	// "process" (a separate condor_starter the startd spawns and hands the
	// syscall connection to over a Unix socket via SCM_RIGHTS). STARTER_MODE.
	StarterMode string
	// StarterPath is the condor_starter-equivalent binary spawned in process
	// mode (STARTER config knob). Required when StarterMode == "process".
	StarterPath string
	// StarterSocketDir is the 0700 directory per-claim starter control sockets
	// live under (default $(SPOOL)/ep/starters). Kept short for the macOS
	// sun_path limit.
	StarterSocketDir string
	// KillingTimeout bounds how long a vacating process starter has before the
	// startd SIGKILLs it (KILLING_TIMEOUT; <=0 uses 30s).
	KillingTimeout time.Duration
	// MaxVacateTime is how long a SOFT vacate (DEACTIVATE_CLAIM, SIGTERM) may take
	// before the startd escalates to a hard kill (SIGKILL), mirroring
	// MachineMaxVacateTime -> KILLING_TIMEOUT escalation. <=0 defaults to
	// KillingTimeout.
	MaxVacateTime time.Duration
	// Store, when non-nil, durably records each slot's claim state at every
	// transition (Stage-6 write side of restart survival). Nil disables
	// persistence (Stage 1-5 cores / unit tests).
	Store *persist.Store
}

// Starter-mode constants (STARTER_MODE).
const (
	starterModeGoroutine = "goroutine"
	starterModeProcess   = "process"
)

// Core is the EP's single-writer event loop. Construct with New, register its
// command handlers with RegisterCommands, drive with Start/Stop.
type Core struct {
	log      *logging.Logger
	slots    []*slot.Slot
	adv      *advertise.Advertiser
	interval time.Duration

	minter       *claim.Minter
	cache        *security.SessionCache
	alivesMissed int
	matchTimeout time.Duration
	// matchCancels holds each Matched slot's match-timeout canceller (canceled by
	// REQUEST_CLAIM or release). Touched only from the event loop.
	matchCancels map[string]context.CancelFunc
	// byName indexes slots by Name for the claim transitions. Built in New and
	// mutated (dslot add/remove) only from the event loop.
	byName map[string]*slot.Slot

	// slotsMu guards dslots (the live dynamic-slot set carved from p-slots): the
	// event loop is the only writer, but the advertiser and query handler read the
	// live slot set (LiveSlots) from other goroutines.
	slotsMu sync.RWMutex
	dslots  []*slot.Slot
	// dslotSeq monotonically numbers carved dynamic slots (the _M in slotN_M).
	// Loop-only.
	dslotSeq int
	// aliveCancels holds each claimed slot's ALIVE-loop cancel func. Touched only
	// from the event loop.
	aliveCancels map[string]context.CancelFunc

	// Starter management (Stage 3). All touched only from the event loop.
	executeDir    string
	starterUpdate time.Duration
	uidDomain     string
	fsDomain      string
	activations   map[string]*activation
	sandboxSeq    int64

	// Process-starter management (Stage 6). Touched only from the event loop.
	starterMode      string
	starterPath      string
	starterSocketDir string
	killingTimeout   time.Duration
	maxVacateTime    time.Duration
	store            *persist.Store
	persister        *persister

	// activationGen numbers activations so a stale vacate-escalation timer never
	// kills a later activation on the same slot. Loop-only.
	activationGen int64
	// deferredDeactivate holds, per slot, a channel closed when the starter reaps
	// so a stashed DEACTIVATE_CLAIM_JOB_DONE (413) reply can then be sent.
	// Loop-only.
	deferredDeactivate map[string]chan struct{}

	events chan Event

	cancel   context.CancelFunc
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// New builds a Core. When Minter is set it pre-mints each slot's Unclaimed claim
// id so the private ad advertises a ClaimId from the first round.
func New(opts Options) *Core {
	interval := opts.UpdateInterval
	if interval <= 0 {
		interval = 300 * time.Second
	}
	alivesMissed := opts.AlivesMissed
	if alivesMissed <= 0 {
		alivesMissed = claim.DefaultAlivesMissed
	}
	matchTimeout := opts.MatchTimeout
	if matchTimeout <= 0 {
		matchTimeout = 120 * time.Second
	}
	c := &Core{
		log:          opts.Logger,
		slots:        opts.Slots,
		adv:          opts.Advertiser,
		interval:     interval,
		minter:       opts.Minter,
		cache:        opts.SessionCache,
		alivesMissed: alivesMissed,
		matchTimeout: matchTimeout,
		byName:       make(map[string]*slot.Slot, len(opts.Slots)),
		aliveCancels: make(map[string]context.CancelFunc),
		matchCancels: make(map[string]context.CancelFunc),

		executeDir:    opts.ExecuteDir,
		starterUpdate: opts.StarterUpdateInterval,
		uidDomain:     opts.UIDDomain,
		fsDomain:      opts.FileSystemDomain,
		activations:   make(map[string]*activation),

		starterMode:        starterMode(opts.StarterMode),
		starterPath:        opts.StarterPath,
		starterSocketDir:   opts.StarterSocketDir,
		killingTimeout:     killingTimeout(opts.KillingTimeout),
		maxVacateTime:      maxVacateTime(opts.MaxVacateTime, opts.KillingTimeout),
		store:              opts.Store,
		deferredDeactivate: make(map[string]chan struct{}),

		events: make(chan Event, 64),
	}
	for _, s := range opts.Slots {
		c.byName[s.Name] = s
	}
	if c.store != nil {
		c.persister = newPersister(c.store, c.log)
	}
	c.prime()
	return c
}

// Slots returns the core's CONFIGURED slot set (static slots or p-slots; fixed
// at construction). Dynamic slots are not included -- use LiveSlots for the full
// advertised/queryable set.
func (c *Core) Slots() []*slot.Slot { return c.slots }

// LiveSlots returns a snapshot of every slot the startd currently advertises and
// serves queries from: the configured slots plus every live dynamic slot carved
// from a p-slot. Safe to call from any goroutine (the advertiser and query
// handler do); the event loop is the only writer of the dslot set.
func (c *Core) LiveSlots() []*slot.Slot {
	c.slotsMu.RLock()
	defer c.slotsMu.RUnlock()
	out := make([]*slot.Slot, 0, len(c.slots)+len(c.dslots))
	out = append(out, c.slots...)
	out = append(out, c.dslots...)
	return out
}

// addDSlot registers a freshly carved dynamic slot (loop-only): it joins byName
// and the live dslot set. re-advertising then enumerates it.
func (c *Core) addDSlot(d *slot.Slot) {
	c.byName[d.Name] = d
	c.slotsMu.Lock()
	c.dslots = append(c.dslots, d)
	c.slotsMu.Unlock()
}

// removeDSlot drops a destroyed dynamic slot from byName and the live set
// (loop-only).
func (c *Core) removeDSlot(name string) {
	delete(c.byName, name)
	c.slotsMu.Lock()
	for i, d := range c.dslots {
		if d.Name == name {
			c.dslots = append(c.dslots[:i], c.dslots[i+1:]...)
			break
		}
	}
	c.slotsMu.Unlock()
}

// starterMode normalizes the STARTER_MODE knob (default goroutine).
func starterMode(v string) string {
	if v == starterModeProcess {
		return starterModeProcess
	}
	return starterModeGoroutine
}

// killingTimeout defaults KILLING_TIMEOUT to 30s.
func killingTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return 30 * time.Second
	}
	return d
}

// maxVacateTime defaults the soft-vacate escalation window to KILLING_TIMEOUT
// (itself defaulting to 30s) when unset.
func maxVacateTime(d, killing time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return killingTimeout(killing)
}

// persistSlot durably records a slot's current claim state (Stage-6 write side
// of restart survival). No-op when no Store is configured. Loop-only: it reads
// the slot's claim + any running activation (both owned by the event loop) to
// build the record IN MEMORY, then hands it to the async persister. The actual
// store.Put (which msyncs mapped pages) happens off the event loop -- a
// synchronous Put here stalls the single-writer loop long enough to blow the
// timing-sensitive claim/activate handshake with a real schedd/shadow.
func (c *Core) persistSlot(s *slot.Slot) {
	if c.persister == nil || s == nil {
		return
	}
	cl := s.Claim()
	if cl == nil {
		return
	}
	rec := persist.Record{
		SlotName:      s.Name,
		ClaimID:       cl.ClaimID(),
		PublicClaimID: cl.PublicClaimID(),
		State:         s.State(),
		Activity:      s.Activity(),
		SlotType:      s.SlotType,
		ScheddAddr:    cl.ScheddAddr(),
		ScheddName:    cl.ScheddName(),
		User:          cl.User(),
		ClientMachine: cl.ClientMachine(),
		AliveInterval: cl.AliveInterval(),
		Entered:       cl.EnteredCurrentState(),
	}
	// A dynamic slot records its parent + carved resources so a restarted startd
	// can recreate it and subtract from the rebuilt p-slot (Stage-8 re-adoption).
	if s.IsDynamic() {
		res := s.Resources()
		rec.ParentSlotName = s.ParentName
		rec.DSlotSubID = s.SubID
		rec.Cpus = res.Cpus
		rec.MemoryMB = res.MemoryMB
		rec.DiskKB = res.DiskKB
	}
	if !cl.LeaseDeadline().IsZero() {
		rec.LeaseDeadline = cl.LeaseDeadline().Unix()
	}
	if act := c.activations[s.Name]; act != nil {
		rec.StarterPid = act.starterPid
		rec.StarterSocket = act.socketPath
		rec.StarterIpAddr = act.starterAddr
		rec.GlobalJobID = act.globalJID
		rec.Sandbox = act.sandbox
		if act.jobAd != nil {
			rec.JobAd = act.jobAd.StringWithPrivate()
		}
	}
	c.persister.put(rec)
}

// persister writes claim records to the durable store OFF the event loop. It
// coalesces by slot (only the latest state per slot matters for restart
// recovery), so a burst of transitions never queues unbounded work and the
// event loop never blocks on disk I/O. A per-Put panic (or error) is contained
// here and cannot take down the loop.
type persister struct {
	store *persist.Store
	log   *logging.Logger

	mu      sync.Mutex
	pending map[string]persist.Record
	wake    chan struct{}
	done    chan struct{}
	wg      sync.WaitGroup
}

func newPersister(store *persist.Store, log *logging.Logger) *persister {
	return &persister{
		store:   store,
		log:     log,
		pending: make(map[string]persist.Record),
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
}

func (p *persister) start() {
	p.wg.Add(1)
	go p.run()
}

// put queues a record (latest-per-slot) and signals the writer. Non-blocking:
// safe to call from the event loop.
func (p *persister) put(rec persist.Record) {
	p.mu.Lock()
	p.pending[rec.SlotName] = rec
	p.mu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

func (p *persister) run() {
	defer p.wg.Done()
	for {
		select {
		case <-p.wake:
			p.flush()
		case <-p.done:
			p.flush() // final drain
			return
		}
	}
}

func (p *persister) flush() {
	p.mu.Lock()
	if len(p.pending) == 0 {
		p.mu.Unlock()
		return
	}
	batch := p.pending
	p.pending = make(map[string]persist.Record)
	p.mu.Unlock()
	for _, rec := range batch {
		p.commit(rec)
	}
}

// commit performs one store.Put with panic containment.
func (p *persister) commit(rec persist.Record) {
	defer func() {
		if r := recover(); r != nil {
			p.log.Warn(logging.DestinationGeneral, "claim-store commit panicked (contained)",
				"slot", rec.SlotName, "recover", fmt.Sprint(r))
		}
	}()
	if err := p.store.Put(rec); err != nil {
		p.log.Warn(logging.DestinationGeneral, "persisting claim record failed",
			"slot", rec.SlotName, "err", err.Error())
	}
}

func (p *persister) stop() {
	close(p.done)
	p.wg.Wait()
}

// Submit enqueues an event for the loop. Safe from any goroutine.
func (c *Core) Submit(ev Event) {
	select {
	case c.events <- ev:
	default:
		c.log.Warn(logging.DestinationGeneral, "startd event queue full; dropping event")
	}
}

// Start launches the event-loop goroutine (and the async claim persister).
func (c *Core) Start(ctx context.Context) {
	ctx, c.cancel = context.WithCancel(ctx)
	if c.persister != nil {
		c.persister.start()
	}
	c.wg.Add(1)
	go c.loop(ctx)
}

// Stop cancels the loop (which invalidates the slots' ads best-effort) and waits
// for it to exit. Idempotent.
//
// Stage-7 restart survival: Stop deliberately does NOT vacate or kill running
// starters. In PROCESS mode the starter is a separate process holding the job's
// process group and the shadow syscall socket, so it keeps the job running when
// the startd exits and waits (on its durable control socket) to be redialed by
// the restarted startd -- the whole point of restart survival. (GOROUTINE-mode
// starters are in-process and necessarily stop with the startd; only process
// mode survives.) Contrast RELEASE_CLAIM / DEACTIVATE from the schedd, which DO
// tear the starter down -- only a startd *restart* preserves it.
func (c *Core) Stop() {
	// Fully idempotent: the entire teardown runs once, so a second Stop (e.g. an
	// explicit Stop plus a deferred/Cleanup one) is a no-op rather than a
	// double-close of the persister's done channel.
	c.stopOnce.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
		c.wg.Wait()
		// Flush and stop the persister AFTER the loop has quiesced, so the last
		// transitions it enqueued reach disk before the store is closed (main
		// closes the store after Stop via LIFO defers).
		if c.persister != nil {
			c.persister.stop()
		}
	})
}

func (c *Core) loop(ctx context.Context) {
	defer c.wg.Done()

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	c.log.Info(logging.DestinationGeneral, "startd core started",
		"slots", len(c.slots), "update_interval", c.interval.String())

	// Advertise immediately on startup so the slots appear without waiting a
	// full interval.
	if c.adv != nil {
		c.adv.Advertise(ctx)
	}

	for {
		select {
		case <-ctx.Done():
			c.log.Info(logging.DestinationGeneral, "startd core stopping; invalidating slot ads")
			if c.adv != nil {
				// The serve context is already cancelled, so invalidate on a
				// fresh bounded context.
				ictx, icancel := context.WithTimeout(context.Background(), 10*time.Second)
				c.adv.Invalidate(ictx)
				icancel()
			}
			return
		case <-ticker.C:
			if c.adv != nil {
				c.adv.Advertise(ctx)
			}
		case ev := <-c.events:
			c.handle(ctx, ev)
		}
	}
}

func (c *Core) handle(ctx context.Context, ev Event) {
	switch e := ev.(type) {
	case evReschedule:
		if c.adv != nil {
			c.adv.Advertise(ctx)
		}
	case evMatchInfo:
		c.doMatchInfo(ctx, e)
	case evMatchTimeout:
		c.doMatchTimeout(ctx, e)
	case evRequestClaim:
		c.doRequestClaim(ctx, e)
	case evReleaseClaim:
		c.doReleaseByClaimID(ctx, e.claimID, "RELEASE_CLAIM")
	case evReleaseSlot:
		if s := c.byName[e.slotName]; s != nil {
			c.releaseSlot(ctx, s, e.reason)
		}
	case evAliveOK:
		c.doAliveOK(e.slotName)
	case evActivateClaim:
		c.doActivateClaim(ctx, e)
	case evStarterUpdate:
		c.doStarterUpdate(e)
	case evStarterFinal:
		c.doStarterFinal(e)
	case evStarterExited:
		c.doStarterExited(ctx, e.slotName)
	case evStarterHello:
		c.doStarterHello(e)
	case evLocateStarter:
		e.reply <- c.doLocateStarter(e.claimID, e.globalJobID)
	case evAdopt:
		c.doAdopt(ctx)
		close(e.done)
	case evAdoptFailed:
		c.doAdoptFailed(ctx, e.slotName)
	case evDeactivate:
		c.doDeactivate(e)
	case evVacate:
		c.doVacate(ctx, e)
	case evVacateEscalate:
		c.doVacateEscalate(e)
	default:
		c.log.Debug(logging.DestinationGeneral, "startd core received unknown event")
	}
}

// RegisterCommands wires the EP's command handlers onto the shared cedar command
// server: the query/state surface (READ, matching the C++ startd) and, when
// claiming is enabled (a Minter was supplied), the claim surface
// (REQUEST_CLAIM/RELEASE_CLAIM).
func (c *Core) RegisterCommands(srv *cedarserver.Server) {
	srv.Handle(int(commands.QUERY_STARTD_ADS), c.handleQueryStartdAds, "READ")
	srv.Handle(int(commands.GIVE_STATE), c.handleGiveState, "READ")
	// CA_CMD/CA_LOCATE_STARTER (Stage 7): a reconnecting shadow, riding the claim
	// session, asks where the starter for its job is. Answered from live +
	// persisted claim state.
	srv.Handle(reconnect.CACmd, reconnect.StartdHandler(c.locateStarter, c.log), "READ", "DAEMON")
	if c.minter != nil {
		c.RegisterClaimCommands(srv)
	}
}

// locateStarter bridges a CA_LOCATE_STARTER handler (a cedar server goroutine)
// to the single-writer loop, which owns the live+persisted claim state.
func (c *Core) locateStarter(claimID, globalJobID string) reconnect.LocateResult {
	reply := make(chan reconnect.LocateResult, 1)
	c.Submit(evLocateStarter{claimID: claimID, globalJobID: globalJobID, reply: reply})
	select {
	case r := <-reply:
		return r
	case <-time.After(5 * time.Second):
		return reconnect.LocateResult{}
	}
}

// handleQueryStartdAds serves QUERY_STARTD_ADS: read the query ad, then stream
// each matching slot's public ad as PutInt(1)+putClassAd, terminated by
// PutInt(0)+EOM (command.cpp:744-792; the same wire golang-collector serves).
func (c *Core) handleQueryStartdAds(ctx context.Context, conn *cedarserver.Conn) error {
	req := conn.Message
	if req == nil {
		req = message.NewMessageFromStream(conn.Stream)
	}
	queryAd, err := req.GetClassAd(ctx)
	if err != nil {
		return err
	}
	query, projection := parseQuery(queryAd)

	resp := message.NewMessageForStream(conn.Stream)
	for _, s := range c.LiveSlots() {
		ad := s.PublicAd()
		if query != nil && !query.Matches(ad) {
			continue
		}
		out := ad
		if len(projection) > 0 {
			out = project(ad, projection)
		}
		if err := resp.PutInt(ctx, 1); err != nil {
			return err
		}
		if err := resp.PutClassAd(ctx, out); err != nil {
			return err
		}
	}
	if err := resp.PutInt(ctx, 0); err != nil {
		return err
	}
	return resp.FlushFrame(ctx, true)
}

// handleGiveState serves GIVE_STATE (448): put the machine's state string. With
// multiple slots the startd reports the first slot's state; in Stage 1 every
// slot is Unclaimed.
func (c *Core) handleGiveState(ctx context.Context, conn *cedarserver.Conn) error {
	state := "Unclaimed"
	if len(c.slots) > 0 {
		state = c.slots[0].State()
	}
	resp := message.NewMessageForStream(conn.Stream)
	if err := resp.PutString(ctx, state); err != nil {
		return err
	}
	return resp.FlushFrame(ctx, true)
}

// parseQuery extracts a constraint (nil = match all) and projection whitelist
// from a collector query ad. It accepts the tools' whitespace-separated
// Projection and the Go client's comma-separated ProjectionAttributes.
func parseQuery(queryAd *classad.ClassAd) (*vm.Query, []string) {
	var query *vm.Query
	if expr, ok := queryAd.Lookup("Requirements"); ok && expr != nil {
		s := strings.TrimSpace(expr.String())
		if s != "" && !strings.EqualFold(s, "true") {
			if q, err := vm.Parse(s); err == nil {
				query = q
			}
		}
	}
	var projection []string
	for _, attr := range []string{"Projection", "ProjectionAttributes"} {
		if s, ok := queryAd.EvaluateAttrString(attr); ok && strings.TrimSpace(s) != "" {
			for _, p := range strings.FieldsFunc(s, func(r rune) bool {
				return r == ',' || r == ' ' || r == '\t' || r == '\n'
			}) {
				if p != "" {
					projection = append(projection, p)
				}
			}
			break
		}
	}
	return query, projection
}

// project returns a copy of ad with only the whitelisted attributes present.
func project(ad *classad.ClassAd, attrs []string) *classad.ClassAd {
	out := classad.New()
	for _, a := range attrs {
		if e, ok := ad.Lookup(a); ok {
			out.InsertExpr(a, e)
		}
	}
	return out
}
