// Package claim implements the EP's per-slot claim records, claim-id minting,
// and the small Unclaimed -> Claimed/Idle state machine the startd's event loop
// drives. It is the server-side mirror of golang-cedar/security's claim import
// path: every slot is handed a freshly minted claim id (a "match password"
// security session capability) at creation, and REQUEST_CLAIM/RELEASE_CLAIM
// transitions swap that claim for a Claimed record (storing the schedd's
// address, alive interval, and client identity) or mint a fresh Unclaimed one.
//
// A claim record is only ever mutated by the single-writer startd event loop, so
// it carries no internal locking; the slot that owns it guards the pointer swap.
//
// Ground truth: src/condor_startd.V6/claim.cpp (newIdString / ClaimId ctor for
// minting; the Unclaimed -> Claimed/Idle lifecycle) and the command wire in
// src/condor_startd.V6/command.cpp:985 (command_request_claim).
package claim

import (
	"sync/atomic"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
)

// Claim command integers. cedar/commands already defines REQUEST_CLAIM (442),
// RELEASE_CLAIM (443), ACTIVATE_CLAIM (444), DEACTIVATE_CLAIM (403) and ALIVE
// (441); the three DEACTIVATE variants below are not in that package, so we
// define them locally (SCHED_VERS+offset, condor_commands.h) to complete the
// claim command surface the minted session must authorize.
const (
	CmdReleaseClaim            = int(commands.RELEASE_CLAIM)    // 443
	CmdRequestClaim            = int(commands.REQUEST_CLAIM)    // 442
	CmdActivateClaim           = int(commands.ACTIVATE_CLAIM)   // 444
	CmdDeactivateClaim         = int(commands.DEACTIVATE_CLAIM) // 403
	CmdMatchInfo               = int(commands.MATCH_INFO)       // 440
	CmdAlive                   = int(commands.ALIVE)            // 441
	CmdDeactivateClaimForcibly = 404
	CmdDeactivateClaimJobDone  = 413
	CmdDeactivateFinalXfer     = 561
)

// claimSurfaceCommands is the full set of command integers a minted claim
// session authorizes: every claim/lease command a schedd may send the startd
// over the session, plus ALIVE (which the startd sends the schedd). Mirrors the
// commands a C++ startd maps onto the match session.
var claimSurfaceCommands = []int{
	CmdRequestClaim, CmdReleaseClaim, CmdActivateClaim,
	CmdDeactivateClaim, CmdDeactivateClaimForcibly, CmdDeactivateClaimJobDone,
	CmdDeactivateFinalXfer, CmdMatchInfo, CmdAlive,
}

// SurfaceCommands returns the command integers a claim-derived session must
// authorize (every claim/lease command over the session, plus ALIVE). Stage-7
// re-adoption passes these to security.ImportClaimSession so the re-registered
// match session authorizes inbound claim/CA commands after a restart.
func SurfaceCommands() []int {
	out := make([]int, len(claimSurfaceCommands))
	copy(out, claimSurfaceCommands)
	return out
}

// DefaultAlivesMissed is the number of consecutive ALIVE keepalives a claim may
// miss before its lease is considered expired (MAX_CLAIM_ALIVES_MISSED). The
// lease length is AlivesMissed * AliveInterval.
const DefaultAlivesMissed = 6

// State is a claim's lifecycle state: Unclaimed, Claimed/Idle (Stage 2), and
// Claimed/Busy (Stage 3: a starter is running an activated job).
type State int

const (
	// Unclaimed is a free slot carrying a pre-minted (but unused) claim id.
	Unclaimed State = iota
	// ClaimedIdle is a slot claimed by a schedd with no job activated yet.
	ClaimedIdle
	// ClaimedBusy is a claimed slot with an activated job (a starter running).
	ClaimedBusy
)

func (s State) String() string {
	switch s {
	case ClaimedIdle, ClaimedBusy:
		return "Claimed"
	default:
		return "Unclaimed"
	}
}

// IsClaimed reports whether the claim is in either claimed state.
func (s State) IsClaimed() bool { return s == ClaimedIdle || s == ClaimedBusy }

// StateName returns the HTCondor State string ("Unclaimed"/"Claimed") a slot ad
// advertises for this claim state.
func (s State) StateName() string { return s.String() }

// Minter mints claim ids for a single startd: it holds the daemon's advertised
// sinful, its birthdate (process start time), the shared session cache the
// minted sessions register into, and a monotonically increasing sequence
// counter. All minted sessions land in the same cache the startd's cedar server
// resumes from, so a schedd presenting the claim id resumes the pre-shared
// session inbound with no fresh DC_AUTHENTICATE.
type Minter struct {
	cache     *security.SessionCache
	sinful    string
	birthdate int64
	seq       atomic.Int64
}

// MinterOptions configures a Minter.
type MinterOptions struct {
	// Cache is the session cache the minted sessions register into. It MUST be
	// the same cache the startd's cedar server was built with
	// (SecurityConfig.SessionCache) so inbound resumption finds the session.
	// Required.
	Cache *security.SessionCache
	// Sinful is the startd's advertised command address (the leading component
	// of every claim id). Required.
	Sinful string
	// Birthdate is the startd's process start time (unix seconds), the claim
	// id's startd_bday component.
	Birthdate int64
}

// NewMinter builds a Minter.
func NewMinter(opts MinterOptions) *Minter {
	return &Minter{
		cache:     opts.Cache,
		sinful:    opts.Sinful,
		birthdate: opts.Birthdate,
	}
}

// Mint creates a fresh Unclaimed claim: it mints a new claim id (with a new
// sequence number), registering the embedded match session in the Minter's
// cache. The returned claim is Unclaimed until Accept is called.
func (m *Minter) Mint() (*Claim, error) {
	seq := int(m.seq.Add(1))
	minted, err := security.MintClaimSession(m.cache, security.MintClaimOptions{
		Sinful:             m.sinful,
		Birthdate:          m.birthdate,
		SequenceNum:        seq,
		ExtraValidCommands: claimSurfaceCommands,
	})
	if err != nil {
		return nil, err
	}
	return &Claim{
		claimID:       minted.ClaimID(),
		publicClaimID: minted.PublicClaimID(),
		sessionID:     minted.SessionID(),
		state:         Unclaimed,
	}, nil
}

// AdoptOptions carries the persisted identity + claimed-state fields used to
// reconstruct a Claim during Stage-7 re-adoption, WITHOUT minting a fresh
// session (the match session is re-registered separately via
// security.ImportClaimSession). The claim id is the full secret id read back
// from the durable store; SessionID is derived from it by the caller
// (security.ParseClaimIDStrict).
type AdoptOptions struct {
	ClaimID       string
	PublicClaimID string
	SessionID     string
	ScheddAddr    string
	ScheddName    string
	User          string
	ClientMachine string
	AliveInterval int
	// Busy reconstructs the claim as Claimed/Busy (a starter was running an
	// activated job at persist time); false reconstructs Claimed/Idle.
	Busy bool
	// LeaseDeadline / Entered are the persisted lease + state-entry timestamps
	// (zero = unset).
	LeaseDeadline time.Time
	Entered       time.Time
}

// Adopt reconstructs a Claimed claim from persisted state during re-adoption.
// The returned claim is Claimed/Idle (or Claimed/Busy when o.Busy) with the
// recorded schedd identity and lease deadline, so the ALIVE loop and inbound
// claim/CA commands behave exactly as before the restart.
func Adopt(o AdoptOptions) *Claim {
	st := ClaimedIdle
	if o.Busy {
		st = ClaimedBusy
	}
	return &Claim{
		claimID:       o.ClaimID,
		publicClaimID: o.PublicClaimID,
		sessionID:     o.SessionID,
		state:         st,
		scheddAddr:    o.ScheddAddr,
		scheddName:    o.ScheddName,
		user:          o.User,
		clientMachine: o.ClientMachine,
		aliveInterval: o.AliveInterval,
		leaseDeadline: o.LeaseDeadline,
		entered:       o.Entered,
	}
}

// Claim is one slot's claim record: the claim id (identity) plus, once claimed,
// the schedd's identity and the lease bookkeeping. Only the startd event loop
// mutates it.
type Claim struct {
	claimID       string
	publicClaimID string
	sessionID     string
	state         State

	// Filled on Accept (claimed state).
	scheddAddr    string
	scheddName    string
	user          string
	clientMachine string
	aliveInterval int
	leaseDeadline time.Time
	entered       time.Time

	// Starter job-monitoring records (Stage 3; written on the event loop from
	// the starter's control-channel Update/Final messages, read by later
	// stages).
	updateAd    *classad.ClassAd
	finalAd     *classad.ClassAd
	finalStatus int
	finalReason int
}

// ClaimID returns the full, SECRET claim id (the capability handed to the
// negotiator via the private ad). Never log this verbatim.
func (c *Claim) ClaimID() string { return c.claimID }

// PublicClaimID returns the secret-elided claim id, safe for logging and for the
// PublicClaimId slot-ad attribute.
func (c *Claim) PublicClaimID() string { return c.publicClaimID }

// SessionID returns the security session id embedded in the claim id.
func (c *Claim) SessionID() string { return c.sessionID }

// State returns the claim's lifecycle state.
func (c *Claim) State() State { return c.state }

// ScheddAddr returns the schedd command sinful ALIVE keepalives go to (claimed).
func (c *Claim) ScheddAddr() string { return c.scheddAddr }

// ScheddName returns the claiming schedd's advertised name (claimed).
func (c *Claim) ScheddName() string { return c.scheddName }

// User returns the claim's remote user (claimed).
func (c *Claim) User() string { return c.user }

// ClientMachine returns the claiming client's machine/host (claimed).
func (c *Claim) ClientMachine() string { return c.clientMachine }

// AliveInterval returns the agreed keepalive interval in seconds (claimed).
func (c *Claim) AliveInterval() int { return c.aliveInterval }

// LeaseDeadline returns when the lease expires absent further ALIVEs (claimed).
func (c *Claim) LeaseDeadline() time.Time { return c.leaseDeadline }

// EnteredCurrentState returns when the claim entered its current state (unix).
func (c *Claim) EnteredCurrentState() int64 {
	if c.entered.IsZero() {
		return 0
	}
	return c.entered.Unix()
}

// AcceptInfo carries the parameters of an accepted REQUEST_CLAIM.
type AcceptInfo struct {
	ScheddAddr    string
	ScheddName    string
	User          string
	ClientMachine string
	AliveInterval int
	AlivesMissed  int // MAX_CLAIM_ALIVES_MISSED; <=0 uses DefaultAlivesMissed
	Now           time.Time
}

// Accept transitions an Unclaimed claim to Claimed/Idle, recording the schedd
// identity and computing the initial lease deadline
// (now + AlivesMissed*AliveInterval).
func (c *Claim) Accept(info AcceptInfo) {
	now := info.Now
	if now.IsZero() {
		now = time.Now()
	}
	c.state = ClaimedIdle
	c.scheddAddr = info.ScheddAddr
	c.scheddName = info.ScheddName
	c.user = info.User
	c.clientMachine = info.ClientMachine
	c.aliveInterval = info.AliveInterval
	c.entered = now
	c.leaseDeadline = now.Add(LeaseDuration(info.AliveInterval, info.AlivesMissed))
}

// SetBusy transitions Claimed/Idle -> Claimed/Busy (an ACTIVATE_CLAIM was
// accepted and a starter spawned). Loop-only.
func (c *Claim) SetBusy(now time.Time) {
	c.state = ClaimedBusy
	c.entered = now
}

// SetIdle transitions Claimed/Busy -> Claimed/Idle (the starter exited; the
// claim survives, per C++ semantics the schedd decides the next move).
// Loop-only.
func (c *Claim) SetIdle(now time.Time) {
	c.state = ClaimedIdle
	c.entered = now
}

// SetUpdateAd records the starter's latest periodic Update ad. Loop-only.
func (c *Claim) SetUpdateAd(ad *classad.ClassAd) { c.updateAd = ad }

// UpdateAd returns the starter's latest periodic Update ad (may be nil).
func (c *Claim) UpdateAd() *classad.ClassAd { return c.updateAd }

// SetFinal records the starter's Final message: the final job ad plus the raw
// waitpid status and JOB_* reason code. Loop-only.
func (c *Claim) SetFinal(ad *classad.ClassAd, status, reason int) {
	c.finalAd = ad
	c.finalStatus = status
	c.finalReason = reason
}

// Final returns the starter's recorded Final ad + waitpid status + reason.
func (c *Claim) Final() (*classad.ClassAd, int, int) {
	return c.finalAd, c.finalStatus, c.finalReason
}

// ExtendLease pushes the lease deadline forward by one lease duration from now
// (called on each successful ALIVE keepalive).
func (c *Claim) ExtendLease(alivesMissed int, now time.Time) {
	c.leaseDeadline = now.Add(LeaseDuration(c.aliveInterval, alivesMissed))
}

// LeaseDuration returns the claim lease length for an alive interval:
// alivesMissed * aliveInterval seconds. Non-positive inputs fall back to safe
// defaults so a lease is never zero-length.
func LeaseDuration(aliveInterval, alivesMissed int) time.Duration {
	if alivesMissed <= 0 {
		alivesMissed = DefaultAlivesMissed
	}
	if aliveInterval <= 0 {
		aliveInterval = 1
	}
	return time.Duration(alivesMissed*aliveInterval) * time.Second
}

// AlivePeriod returns how often the startd sends ALIVE keepalives to the schedd:
// lease/3, matching the C++ startd's sendAlive timer (claim.cpp). At the default
// 6 alives-missed this is 2*aliveInterval.
func AlivePeriod(aliveInterval, alivesMissed int) time.Duration {
	d := LeaseDuration(aliveInterval, alivesMissed) / 3
	if d <= 0 {
		d = time.Second
	}
	return d
}
