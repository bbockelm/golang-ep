package startd

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/message"
	cedarserver "github.com/bbockelm/cedar/server"
	hstartd "github.com/bbockelm/golang-htcondor/startd"

	"github.com/bbockelm/golang-htcondor/logging"

	"github.com/bbockelm/golang-ep/internal/claim"
	"github.com/bbockelm/golang-ep/internal/slot"
)

// REQUEST_CLAIM reply codes (condor_commands.h; mirror hstartd's reader).
const (
	replyNotOK      = 0 // claim rejected
	replyOK         = 1 // claim accepted
	replyLeftovers  = 3 // p-slot leftovers: PLAINTEXT leftover claim id + p-slot ad
	replyLeftovers2 = 5 // p-slot leftovers: SECRET (encrypted) leftover claim id
	replySlotAd     = 7 // a claimed slot ad follows (SEND_CLAIMED_AD)
)

// --- Events driving claim transitions on the single-writer loop ---

// claimedSlotReply is one (claim id, slot ad) the reply sends under a
// REQUEST_CLAIM_SLOT_AD (code 7) frame.
type claimedSlotReply struct {
	claimID string
	ad      *classad.ClassAd
}

// leftoverReply carries the partitionable-slot leftovers block (terminal code
// 3/5 + leftover claim id + p-slot ad) so a schedd can claim more dslots from
// the same p-slot.
type leftoverReply struct {
	secure  bool // true => code 5 (encrypted id); false => code 3 (plaintext)
	claimID string
	ad      *classad.ClassAd
}

// claimDecision is the event loop's answer to a REQUEST_CLAIM, handed back to
// the (blocked) cedar handler so it can write the wire reply. On accept it may
// carry claimed slot ads (code 7 loop, SEND_CLAIMED_AD) and, for a p-slot,
// leftovers (terminal code 3/5). With no leftovers the terminal code is OK=1.
type claimDecision struct {
	accept       bool
	claimedSlots []claimedSlotReply
	leftovers    *leftoverReply
}

// evRequestClaim asks the loop to validate + accept a REQUEST_CLAIM. The handler
// blocks on reply until the loop decides.
type evRequestClaim struct {
	claimID       string
	reqAd         *classad.ClassAd
	scheddAddr    string
	aliveInterval int
	clientMachine string
	reply         chan claimDecision
}

// evMatchInfo asks the loop to note a negotiator match for a claim id
// (MATCH_INFO: Unclaimed -> Matched + MATCH_TIMEOUT timer; no reply).
type evMatchInfo struct{ claimID string }

// evMatchTimeout fires when a Matched slot's MATCH_TIMEOUT elapses without a
// REQUEST_CLAIM: the slot returns to Unclaimed and the matched claim id is
// invalidated (a fresh one is minted). claimID guards against a stale timer
// (the slot was re-matched/claimed/released since).
type evMatchTimeout struct {
	slotName string
	claimID  string
}

// evReleaseClaim asks the loop to release the claim matching a claim id
// (RELEASE_CLAIM: no reply to the client).
type evReleaseClaim struct{ claimID string }

// evReleaseSlot asks the loop to release a named slot (from the ALIVE loop when
// the schedd forgot the claim or the lease expired).
type evReleaseSlot struct {
	slotName string
	reason   string
}

// evAliveOK reports a successful keepalive so the loop can extend the lease
// deadline it advertises.
type evAliveOK struct{ slotName string }

func (evRequestClaim) isEvent() {}
func (evMatchInfo) isEvent()    {}
func (evMatchTimeout) isEvent() {}
func (evReleaseClaim) isEvent() {}
func (evReleaseSlot) isEvent()  {}
func (evAliveOK) isEvent()      {}

// prime mints each slot's initial Unclaimed claim id so the private ad carries a
// ClaimId even before any claim request (the negotiator obtains the capability
// this way). Called once from New, before the loop starts, so it needs no lock.
func (c *Core) prime() {
	if c.minter == nil {
		return
	}
	for _, s := range c.slots {
		cl, err := c.minter.Mint()
		if err != nil {
			c.log.Error(logging.DestinationGeneral, "minting initial claim failed",
				"slot", s.Name, "err", err.Error())
			continue
		}
		s.SetClaim(cl)
	}
}

// RegisterClaimCommands wires the claim surface onto the shared cedar server:
// REQUEST_CLAIM/RELEASE_CLAIM (Stage 2), ACTIVATE_CLAIM (Stage 3), and the
// DEACTIVATE_CLAIM variants (Stage-3 stubs; real vacate lands in Stage 8). All
// ride the claim-derived match session the startd minted, so the server resumes
// it (no fresh DC_AUTHENTICATE) out of the shared SessionCache. They are
// registered at DAEMON, matching the C++ startd (command.cpp).
func (c *Core) RegisterClaimCommands(srv *cedarserver.Server) {
	// MATCH_INFO comes from the NEGOTIATOR (a different peer/permission than the
	// schedd's claim commands); it rides the claim-derived match session the
	// negotiator obtained from the private ad.
	srv.Handle(claim.CmdMatchInfo, c.handleMatchInfo, "NEGOTIATOR")
	srv.Handle(claim.CmdRequestClaim, c.handleRequestClaim, "DAEMON")
	srv.Handle(claim.CmdReleaseClaim, c.handleReleaseClaim, "DAEMON")
	srv.Handle(claim.CmdActivateClaim, c.handleActivateClaim, "DAEMON")
	for _, cmd := range []int{
		claim.CmdDeactivateClaim, claim.CmdDeactivateClaimForcibly,
		claim.CmdDeactivateClaimJobDone, claim.CmdDeactivateFinalXfer,
	} {
		srv.Handle(cmd, c.handleDeactivateClaim, "DAEMON")
	}
}

// handleRequestClaim serves REQUEST_CLAIM=442 (command.cpp:985). Wire in:
// get_secret(claim id) + getClassAd(request ad) + get(schedd sinful) +
// get(alive interval) [+ optional extra-claims block we ignore for static
// slots] -- all one CEDAR message. On an encrypted claim session a "secret" is
// byte-identical to a string, so we read the claim id with GetString. The
// accept/reject decision (and the claimed slot ad) come from the event loop; we
// only marshal the reply.
func (c *Core) handleRequestClaim(ctx context.Context, conn *cedarserver.Conn) error {
	in := conn.Message
	if in == nil {
		in = message.NewMessageFromStream(conn.Stream)
	}
	claimID, err := in.GetString(ctx)
	if err != nil {
		return err
	}
	reqAd, err := in.GetClassAd(ctx)
	if err != nil {
		return err
	}
	scheddAddr, err := in.GetString(ctx)
	if err != nil {
		return err
	}
	aliveInterval, err := in.GetInt(ctx)
	if err != nil {
		return err
	}
	// Drain the extra-claims block. A real C++ schedd (dc_startd.cpp
	// putExtraClaims, peer >= 8.2.3) ALWAYS writes a trailing put(N) even for a
	// static-slot claim with no preempted dslot claims -- N=0 -- followed by N
	// secrets. Reading it (tolerating io.EOF, which the oracle client that omits
	// the block produces) consumes the inbound message to EOM so a reused claim
	// socket stays byte-aligned. Mirrors command.cpp:1056's lenient code(N).
	if n, gerr := in.GetInt(ctx); gerr == nil && n > 0 {
		for i := 0; i < n; i++ {
			if _, serr := in.GetString(ctx); serr != nil {
				break
			}
		}
	}

	reply := make(chan claimDecision, 1)
	c.Submit(evRequestClaim{
		claimID:       claimID,
		reqAd:         reqAd,
		scheddAddr:    scheddAddr,
		aliveInterval: aliveInterval,
		clientMachine: hostOf(conn.RemoteAddr),
		reply:         reply,
	})

	var dec claimDecision
	select {
	case dec = <-reply:
	case <-ctx.Done():
		return ctx.Err()
	}

	out := message.NewMessageForStream(conn.Stream)
	if !dec.accept {
		if err := out.PutInt(ctx, replyNotOK); err != nil {
			return err
		}
		return out.FinishMessage(ctx)
	}
	// SEND_CLAIMED_AD loop: for each claimed slot, PutInt(7) + put_secret(claim
	// id) + putClassAd(slot ad). On the encrypted claim session put_secret ==
	// PutString (mirrors accept_request_claim_send_slot_ad, command.cpp:1497).
	for _, cs := range dec.claimedSlots {
		if err := out.PutInt(ctx, replySlotAd); err != nil {
			return err
		}
		if err := out.PutString(ctx, cs.claimID); err != nil {
			return err
		}
		if err := out.PutClassAd(ctx, cs.ad); err != nil {
			return err
		}
	}
	// Terminal code: leftovers (3/5) + leftover claim id + p-slot ad for a
	// partitionable claim, else OK=1 (command.cpp:1650-1690).
	if dec.leftovers != nil {
		code := replyLeftovers
		if dec.leftovers.secure {
			code = replyLeftovers2
		}
		if err := out.PutInt(ctx, code); err != nil {
			return err
		}
		if err := out.PutString(ctx, dec.leftovers.claimID); err != nil {
			return err
		}
		if err := out.PutClassAd(ctx, dec.leftovers.ad); err != nil {
			return err
		}
		return out.FinishMessage(ctx)
	}
	if err := out.PutInt(ctx, replyOK); err != nil {
		return err
	}
	return out.FinishMessage(ctx)
}

// handleReleaseClaim serves RELEASE_CLAIM=443 (command.cpp): get_secret(claim
// id) + EOM, NO reply. It just hands the claim id to the loop, which matches it
// to a slot and performs the release.
func (c *Core) handleReleaseClaim(ctx context.Context, conn *cedarserver.Conn) error {
	in := conn.Message
	if in == nil {
		in = message.NewMessageFromStream(conn.Stream)
	}
	claimID, err := in.GetString(ctx)
	if err != nil {
		return err
	}
	c.Submit(evReleaseClaim{claimID: claimID})
	return nil
}

// handleMatchInfo serves MATCH_INFO=440 (command.cpp:703 command_match_info):
// the negotiator sends get_secret(claim id) + EOM to notify the startd that it
// handed this slot's capability to a schedd. Registered at NEGOTIATOR. There is
// NO reply -- the C++ handler only returns TRUE/FALSE to daemonCore. We hand the
// id to the loop, which moves the matching Unclaimed slot to Matched and arms
// the MATCH_TIMEOUT.
func (c *Core) handleMatchInfo(ctx context.Context, conn *cedarserver.Conn) error {
	in := conn.Message
	if in == nil {
		in = message.NewMessageFromStream(conn.Stream)
	}
	claimID, err := in.GetString(ctx)
	if err != nil {
		return err
	}
	c.Submit(evMatchInfo{claimID: claimID})
	return nil
}

// --- Event-loop transition handlers (single-writer; run only from loop) ---

// doMatchInfo notes a negotiator match: the Unclaimed slot whose current claim
// id equals ev.claimID moves to Matched/Idle and arms a MATCH_TIMEOUT timer.
// Matched slots advertise Requirements=False (slot.buildAdLocked) so the
// negotiator will not re-match them. A MATCH_INFO for a slot that is not
// Unclaimed (already Matched/Claimed) or an unknown id is ignored, mirroring
// command.cpp:1955 match_info.
func (c *Core) doMatchInfo(ctx context.Context, ev evMatchInfo) {
	s := c.findSlotByClaimID(ev.claimID)
	if s == nil {
		c.log.Info(logging.DestinationGeneral, "MATCH_INFO ignored: unknown/stale claim id")
		return
	}
	cl := s.Claim()
	if cl == nil || cl.State() != claim.Unclaimed {
		c.log.Info(logging.DestinationGeneral, "MATCH_INFO ignored: slot not Unclaimed", "slot", s.Name)
		return
	}
	if s.State() != "Unclaimed" {
		// Already Matched (duplicate MATCH_INFO): C++ restarts the timer; simplest
		// correct behavior is to leave the existing timer running.
		c.log.Debug(logging.DestinationGeneral, "MATCH_INFO ignored: slot already Matched", "slot", s.Name)
		return
	}

	now := time.Now()
	s.SetStateActivity("Matched", "Idle", now)
	c.persistSlot(s)
	c.startMatchTimer(ctx, s, ev.claimID)
	c.log.Info(logging.DestinationGeneral, "MATCH_INFO: slot Matched",
		"slot", s.Name, "public_claim", cl.PublicClaimID(), "match_timeout", c.matchTimeout.String())
	c.reAdvertise(ctx)
}

// startMatchTimer arms (or replaces) the MATCH_TIMEOUT timer for a Matched slot.
// Loop-only.
func (c *Core) startMatchTimer(ctx context.Context, s *slot.Slot, claimID string) {
	if cancel := c.matchCancels[s.Name]; cancel != nil {
		cancel()
	}
	mctx, cancel := context.WithCancel(ctx)
	c.matchCancels[s.Name] = cancel
	slotName := s.Name
	timeout := c.matchTimeout
	go func() {
		t := time.NewTimer(timeout)
		defer t.Stop()
		select {
		case <-mctx.Done():
		case <-t.C:
			c.Submit(evMatchTimeout{slotName: slotName, claimID: claimID})
		}
	}()
}

// cancelMatchTimer cancels a slot's MATCH_TIMEOUT timer (on REQUEST_CLAIM or
// release). Loop-only; safe if none is armed.
func (c *Core) cancelMatchTimer(slotName string) {
	if cancel := c.matchCancels[slotName]; cancel != nil {
		cancel()
		delete(c.matchCancels, slotName)
	}
}

// doMatchTimeout returns a Matched slot to Unclaimed when no REQUEST_CLAIM
// arrived in time, INVALIDATING the matched claim id by minting a fresh one
// (claim.cpp:709 match_timed_out deletes the old Claim and news a fresh one, so
// a schedd arriving late with the matched id is rejected). Guarded on the still-
// Matched state and the same claim id so a stale timer (slot since re-matched,
// claimed, or released) is a no-op.
func (c *Core) doMatchTimeout(ctx context.Context, ev evMatchTimeout) {
	s := c.byName[ev.slotName]
	if s == nil {
		return
	}
	delete(c.matchCancels, ev.slotName)
	if s.State() != "Matched" {
		return
	}
	cl := s.Claim()
	if cl == nil || cl.ClaimID() != ev.claimID {
		return
	}
	if c.minter != nil {
		if fresh, err := c.minter.Mint(); err != nil {
			c.log.Error(logging.DestinationGeneral, "minting fresh claim on match timeout failed",
				"slot", s.Name, "err", err.Error())
		} else {
			s.SetClaim(fresh)
		}
	}
	s.SetStateActivity("Unclaimed", "Idle", time.Now())
	c.persistSlot(s)
	c.log.Info(logging.DestinationGeneral, "match timed out; slot back to Unclaimed with a fresh claim id",
		"slot", s.Name)
	c.reAdvertise(ctx)
}

// doRequestClaim validates and accepts a REQUEST_CLAIM, replying the decision to
// the blocked handler and, on accept, transitioning the slot to Claimed/Idle,
// starting the ALIVE loop, and re-advertising.
func (c *Core) doRequestClaim(ctx context.Context, ev evRequestClaim) {
	reject := func() { ev.reply <- claimDecision{accept: false} }

	s := c.findSlotByClaimID(ev.claimID)
	if s == nil {
		c.log.Info(logging.DestinationGeneral, "REQUEST_CLAIM rejected: unknown claim id")
		reject()
		return
	}
	cl := s.Claim()
	if cl == nil || cl.State() != claim.Unclaimed {
		c.log.Info(logging.DestinationGeneral, "REQUEST_CLAIM rejected: slot not Unclaimed", "slot", s.Name)
		reject()
		return
	}
	// A REQUEST_CLAIM (the schedd's follow-up to the negotiator's MATCH_INFO)
	// cancels any pending MATCH_TIMEOUT (command.cpp:1035 cancel_match_timer),
	// whether the slot is Unclaimed or Matched.
	c.cancelMatchTimer(s.Name)

	// Evaluate the slot's Requirements (START && WithinResourceLimits) against
	// the request ad: MY = the slot's UNCLAIMED matching ad (MatchAd, never the
	// Requirements=False advertised form -- a Matched slot's PublicAd would
	// reject every job), TARGET = job ad.
	matchAd := s.MatchAd()
	matchAd.SetTarget(ev.reqAd)
	ok, isBool := matchAd.EvaluateAttrBool("Requirements")
	if !isBool || !ok {
		c.log.Info(logging.DestinationGeneral, "REQUEST_CLAIM rejected: Requirements not satisfied", "slot", s.Name)
		reject()
		return
	}

	// A partitionable slot does not itself become Claimed: it CARVES a dynamic
	// slot with the requested resources, subtracts them, and replies with the
	// dslot (code 7) + p-slot leftovers (code 3/5).
	if s.IsPartitionable() {
		c.doRequestClaimPSlot(ctx, ev, s, cl)
		return
	}

	now := time.Now()
	cl.Accept(claim.AcceptInfo{
		ScheddAddr:    ev.scheddAddr,
		ScheddName:    adString(ev.reqAd, "ScheddName"),
		User:          firstNonEmptyAttr(ev.reqAd, "User", "Owner"),
		ClientMachine: ev.clientMachine,
		AliveInterval: ev.aliveInterval,
		AlivesMissed:  c.alivesMissed,
		Now:           now,
	})
	s.SetStateActivity("Claimed", "Idle", now)
	c.persistSlot(s)

	var claimed []claimedSlotReply
	if adBool(ev.reqAd, "_condor_SEND_CLAIMED_AD") {
		claimed = []claimedSlotReply{{claimID: cl.ClaimID(), ad: s.PublicAd()}}
	}

	c.log.Info(logging.DestinationGeneral, "REQUEST_CLAIM accepted",
		"slot", s.Name, "schedd", ev.scheddAddr, "alive_interval", ev.aliveInterval,
		"public_claim", cl.PublicClaimID())

	c.startAliveLoop(ctx, s)

	ev.reply <- claimDecision{accept: true, claimedSlots: claimed}

	c.reAdvertise(ctx)
}

// doRequestClaimPSlot handles a REQUEST_CLAIM against a partitionable slot: it
// validates the request against the p-slot's REMAINING resources, carves a
// dynamic slot with the requested Cpus/Memory/Disk (subtracting them from the
// p-slot), mints the dslot its own claim (Claimed/Idle), and replies with the
// dslot as a claimed slot (code 7) plus the p-slot leftovers (code 3/5) so the
// schedd can claim more dslots. The p-slot itself stays Unclaimed, advertising
// its reduced resources + ChildClaimIds. Loop-only.
func (c *Core) doRequestClaimPSlot(ctx context.Context, ev evRequestClaim, ps *slot.Slot, psClaim *claim.Claim) {
	reject := func(why string) {
		c.log.Info(logging.DestinationGeneral, "REQUEST_CLAIM (p-slot) rejected: "+why, "slot", ps.Name)
		ev.reply <- claimDecision{accept: false}
	}
	if c.minter == nil {
		reject("no minter (claiming disabled)")
		return
	}

	// willingToRun: evaluate the p-slot's Requirements (START &&
	// WithinResourceLimits against its REMAINING resources) against the request ad.
	matchAd := ps.MatchAd()
	matchAd.SetTarget(ev.reqAd)
	if ok, isBool := matchAd.EvaluateAttrBool("Requirements"); !isBool || !ok {
		reject("Requirements not satisfied by remaining resources")
		return
	}

	req := requestedResources(ev.reqAd)
	if !ps.CanCarve(req) {
		reject(fmt.Sprintf("request (cpus=%d mem=%d disk=%d) exceeds remaining (cpus=%d mem=%d disk=%d)",
			req.Cpus, req.MemoryMB, req.DiskKB, ps.Resources().Cpus, ps.Resources().MemoryMB, ps.Resources().DiskKB))
		return
	}

	// Mint the dslot its own claim id and carve it out of the p-slot.
	dClaim, err := c.minter.Mint()
	if err != nil {
		reject("minting dslot claim: " + err.Error())
		return
	}
	now := time.Now()
	c.dslotSeq++
	dslot := slot.NewDynamicSlot(ps, c.dslotSeq, req, now)
	dslot.SetClaim(dClaim)
	dClaim.Accept(claim.AcceptInfo{
		ScheddAddr:    ev.scheddAddr,
		ScheddName:    adString(ev.reqAd, "ScheddName"),
		User:          firstNonEmptyAttr(ev.reqAd, "User", "Owner"),
		ClientMachine: ev.clientMachine,
		AliveInterval: ev.aliveInterval,
		AlivesMissed:  c.alivesMissed,
		Now:           now,
	})
	dslot.SetStateActivity("Claimed", "Idle", now)
	ps.Carve(req)
	c.addDSlot(dslot)
	c.refreshPSlotChildren(ps)

	c.persistSlot(dslot)
	c.persistSlot(ps)

	// The dslot holds the schedd lease (ALIVE keepalives ride its claim).
	c.startAliveLoop(ctx, dslot)

	c.log.Info(logging.DestinationGeneral, "REQUEST_CLAIM carved dynamic slot",
		"pslot", ps.Name, "dslot", dslot.Name,
		"cpus", req.Cpus, "mem_mb", req.MemoryMB, "disk_kb", req.DiskKB,
		"remaining_cpus", ps.Resources().Cpus, "dslot_public_claim", dClaim.PublicClaimID())

	dec := claimDecision{accept: true}
	if adBool(ev.reqAd, "_condor_SEND_CLAIMED_AD") {
		dec.claimedSlots = []claimedSlotReply{{claimID: dClaim.ClaimID(), ad: dslot.PublicAd()}}
	}
	if adBool(ev.reqAd, "_condor_SEND_LEFTOVERS") {
		// Leftover claim id is the p-slot's OWN (persistent) claim id: the schedd
		// re-uses it to claim further dslots. secure=SECURE_CLAIM_ID (code 5 vs 3).
		dec.leftovers = &leftoverReply{
			secure:  adBool(ev.reqAd, "_condor_SECURE_CLAIM_ID"),
			claimID: psClaim.ClaimID(),
			ad:      ps.PublicAd(),
		}
	}
	ev.reply <- dec
	c.reAdvertise(ctx)
}

// refreshPSlotChildren recomputes a p-slot's ChildClaimIds from its live dslots
// (loop-only).
func (c *Core) refreshPSlotChildren(ps *slot.Slot) {
	var ids []string
	c.slotsMu.RLock()
	for _, d := range c.dslots {
		if d.ParentName == ps.Name {
			if cl := d.Claim(); cl != nil {
				ids = append(ids, cl.ClaimID())
			}
		}
	}
	c.slotsMu.RUnlock()
	ps.SetChildClaimIDs(ids)
}

// requestedResources extracts the dslot resource request from a REQUEST_CLAIM
// ad: RequestCpus/RequestMemory(MB)/RequestDisk(KB), honoring the schedd's
// _condor_Request* overrides first (create_dslot, Resource.cpp:4222). Missing
// Cpus defaults to 1; missing Memory/Disk carve 0 (WithinResourceLimits already
// gated the request, so a job that needs them will have set them).
func requestedResources(ad *classad.ClassAd) slot.Resources {
	geti := func(names ...string) int64 {
		for _, n := range names {
			if v, ok := ad.EvaluateAttrInt(n); ok {
				return v
			}
			if v, ok := ad.EvaluateAttrReal(n); ok {
				return int64(v)
			}
		}
		return 0
	}
	cpus := geti("_condor_RequestCpus", "RequestCpus")
	if cpus < 1 {
		cpus = 1
	}
	return slot.Resources{
		Cpus:     int(cpus),
		MemoryMB: geti("_condor_RequestMemory", "RequestMemory"),
		DiskKB:   geti("_condor_RequestDisk", "RequestDisk"),
	}
}

// doReleaseByClaimID releases the slot whose current claim matches claimID.
func (c *Core) doReleaseByClaimID(ctx context.Context, claimID, reason string) {
	s := c.findSlotByClaimID(claimID)
	if s == nil {
		c.log.Debug(logging.DestinationGeneral, "RELEASE for unknown claim id (already released?)")
		return
	}
	c.releaseSlot(ctx, s, reason)
}

// releaseSlot handles RELEASE_CLAIM. A DYNAMIC slot is DESTROYED (its resources
// return to the parent p-slot); a static slot / p-slot is re-minted and returned
// to Unclaimed/Idle. Either way the ALIVE loop stops and any running starter is
// torn down (RELEASE is forcible in C++ send_vacate; graceful shutdown is the
// DEACTIVATE path). Loop-only.
func (c *Core) releaseSlot(ctx context.Context, s *slot.Slot, reason string) {
	c.cancelMatchTimer(s.Name)
	if cancel := c.aliveCancels[s.Name]; cancel != nil {
		cancel()
		delete(c.aliveCancels, s.Name)
	}
	c.killActivation(s.Name, reason)

	if s.IsDynamic() {
		c.destroyDSlot(ctx, s, reason)
		return
	}

	if c.minter != nil {
		fresh, err := c.minter.Mint()
		if err != nil {
			c.log.Error(logging.DestinationGeneral, "minting fresh claim on release failed",
				"slot", s.Name, "err", err.Error())
		} else {
			s.SetClaim(fresh)
		}
	}
	s.SetStateActivity("Unclaimed", "Idle", time.Now())
	c.persistSlot(s)
	c.log.Info(logging.DestinationGeneral, "claim released", "slot", s.Name, "reason", reason)
	c.reAdvertise(ctx)
}

// destroyDSlot tears down a dynamic slot: it returns the dslot's resources to
// its parent p-slot, drops it from the live registry + byName + persistent
// store, refreshes the p-slot's ChildClaimIds, and re-advertises. Any running
// starter must already be torn down (releaseSlot calls killActivation first).
// Loop-only.
func (c *Core) destroyDSlot(ctx context.Context, d *slot.Slot, reason string) {
	c.removeDSlot(d.Name)
	if c.store != nil {
		c.store.Delete(d.Name)
	}
	// Drop the dslot's ad from the collector immediately (it no longer exists).
	if c.adv != nil {
		c.adv.InvalidateSlot(ctx, d)
	}
	if parent := c.byName[d.ParentName]; parent != nil {
		parent.Restore(d.Resources())
		c.refreshPSlotChildren(parent)
		c.persistSlot(parent)
		c.log.Info(logging.DestinationGeneral, "dynamic slot destroyed; resources returned to p-slot",
			"dslot", d.Name, "pslot", parent.Name, "reason", reason,
			"restored_cpus", parent.Resources().Cpus)
	} else {
		c.log.Warn(logging.DestinationGeneral, "dynamic slot destroyed but parent p-slot not found",
			"dslot", d.Name, "parent", d.ParentName, "reason", reason)
	}
	c.reAdvertise(ctx)
}

// doAliveOK extends the advertised lease deadline of a claimed slot.
func (c *Core) doAliveOK(slotName string) {
	s := c.byName[slotName]
	if s == nil {
		return
	}
	if cl := s.Claim(); cl != nil && cl.State().IsClaimed() {
		cl.ExtendLease(c.alivesMissed, time.Now())
	}
}

// findSlotByClaimID returns the slot (static, p-slot, or dynamic) whose current
// claim id equals claimID. Concurrency-safe (LiveSlots snapshots under a lock):
// the DEACTIVATE handler probes it from a cedar server goroutine.
func (c *Core) findSlotByClaimID(claimID string) *slot.Slot {
	for _, s := range c.LiveSlots() {
		if cl := s.Claim(); cl != nil && cl.ClaimID() == claimID {
			return s
		}
	}
	return nil
}

// --- ALIVE lease loop ---

// startAliveLoop launches the per-claim ALIVE keepalive goroutine. Called from
// the event loop; ctx is the loop's context so Stop cancels the keepalive.
func (c *Core) startAliveLoop(ctx context.Context, s *slot.Slot) {
	cl := s.Claim()
	if cl == nil {
		return
	}
	lctx, cancel := context.WithCancel(ctx)
	c.aliveCancels[s.Name] = cancel
	period := claim.AlivePeriod(cl.AliveInterval(), c.alivesMissed)
	lease := claim.LeaseDuration(cl.AliveInterval(), c.alivesMissed)
	go c.aliveLoop(lctx, s.Name, cl.ScheddAddr(), cl.ClaimID(), period, lease)
}

// aliveLoop sends ALIVE=441 to the schedd every period (lease/3). It owns its
// own lease deadline for retry decisions (avoiding a read race on loop state):
// a successful keepalive resets it; on network failure it keeps retrying until
// the deadline passes, then releases; reply -1 (schedd forgot the claim)
// releases immediately. All state changes go through the event loop via Submit.
func (c *Core) aliveLoop(ctx context.Context, slotName, scheddAddr, claimID string, period, lease time.Duration) {
	deadline := time.Now().Add(lease)
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			reply, err := hstartd.SendAlive(ctx, scheddAddr, claimID, c.cache)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				c.log.Warn(logging.DestinationGeneral, "ALIVE send failed",
					"slot", slotName, "err", err.Error())
				if time.Now().After(deadline) {
					c.Submit(evReleaseSlot{slotName: slotName, reason: "lease expired (ALIVE failures)"})
					return
				}
				continue
			}
			if reply == hstartd.AliveScheddForgotClaim {
				c.Submit(evReleaseSlot{slotName: slotName, reason: "schedd forgot claim"})
				return
			}
			deadline = time.Now().Add(lease)
			c.Submit(evAliveOK{slotName: slotName})
		}
	}
}

// reAdvertise pushes the slots' ad pairs immediately (on claim/release
// transitions) in addition to the periodic loop.
func (c *Core) reAdvertise(ctx context.Context) {
	if c.adv != nil {
		c.adv.Advertise(ctx)
	}
}

// --- small ClassAd helpers ---

func adBool(ad *classad.ClassAd, name string) bool {
	if ad == nil {
		return false
	}
	v, ok := ad.EvaluateAttrBool(name)
	return ok && v
}

func adString(ad *classad.ClassAd, name string) string {
	if ad == nil {
		return ""
	}
	v, _ := ad.EvaluateAttrString(name)
	return v
}

func firstNonEmptyAttr(ad *classad.ClassAd, names ...string) string {
	for _, n := range names {
		if v := adString(ad, n); v != "" {
			return v
		}
	}
	return ""
}

// hostOf returns the host portion of a "host:port" address (the peer's machine).
func hostOf(addr string) string {
	if addr == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
