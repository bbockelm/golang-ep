package startd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/golang-htcondor/logging"

	"github.com/bbockelm/golang-ep/internal/claim"
	"github.com/bbockelm/golang-ep/internal/persist"
	"github.com/bbockelm/golang-ep/internal/slot"
	"github.com/bbockelm/golang-ep/internal/starter"
)

// Adopt drives Stage-7 re-adoption: it reconstructs every persisted ACTIVE claim
// (re-registering the match session, rebuilding the slot as Claimed, redialing a
// surviving process starter and resuming the ALIVE lease). It MUST be called
// after Start (it runs on the event loop). It blocks until the synchronous
// reconstruction finishes; the per-claim redials proceed asynchronously.
func (c *Core) Adopt() {
	if c.store == nil {
		return
	}
	done := make(chan struct{})
	c.Submit(evAdopt{done: done})
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		c.log.Warn(logging.DestinationGeneral, "re-adoption reconstruction timed out")
	}
}

// exitMarker mirrors the JSON the process starter drops at <sandbox>/.exit on the
// way out (cmd/starter/main.go). Re-adoption reads it when a starter died while
// the startd was down, to recover the job's terminal outcome.
type exitMarker struct {
	WaitpidStatus int    `json:"waitpid_status"`
	Reason        int    `json:"reason"`
	FinalAd       string `json:"final_ad,omitempty"`
	ExitTime      int64  `json:"exit_time"`
}

// doAdopt reconstructs claimed slots from the durable store. Loop-only. For each
// persisted Claimed record it: (a) re-registers the claim-derived match session
// so ALIVE and inbound claim/CA commands authenticate; (b) rebuilds the slot's
// Claim as Claimed/Idle or Claimed/Busy; (c) for a Busy claim, reconstructs the
// activation and redials the surviving starter (Reattach/Hello, async); and
// (d) resumes the ALIVE lease loop.
func (c *Core) doAdopt(ctx context.Context) {
	records := c.store.List()
	adopted := 0
	touchedParents := make(map[string]*slot.Slot)
	for _, rec := range records {
		if !strings.EqualFold(rec.State, "Claimed") {
			continue // only live claims survive a restart
		}
		// A dynamic-slot record is not in byName (config only builds static
		// slots / p-slots): recreate the dslot, carving it out of its rebuilt
		// parent p-slot, before the lookup below finds it.
		if strings.EqualFold(rec.SlotType, slot.SlotTypeDynamic) {
			if d := c.reconstructDSlot(rec); d != nil {
				if p := c.byName[rec.ParentSlotName]; p != nil {
					touchedParents[p.Name] = p
				}
			} else {
				c.log.Warn(logging.DestinationGeneral,
					"re-adoption: dynamic-slot record whose parent p-slot is gone; dropping",
					"dslot", rec.SlotName, "parent", rec.ParentSlotName)
				c.store.Delete(rec.SlotName)
				continue
			}
		}
		s := c.byName[rec.SlotName]
		if s == nil {
			c.log.Warn(logging.DestinationGeneral,
				"re-adoption: persisted claim for a slot this config no longer defines; dropping record",
				"slot", rec.SlotName)
			c.store.Delete(rec.SlotName)
			continue
		}
		if rec.ClaimID == "" {
			continue
		}

		// (a) Re-register the match session (we minted the id; Import reconstitutes
		// the same non-negotiated session, so nothing renegotiates).
		if _, err := security.ImportClaimSession(c.cache, rec.ClaimID, security.ClaimSessionOptions{
			PeerFQU:            security.SubmitSideMatchSessionFQU,
			PeerAddr:           rec.ScheddAddr,
			ExtraValidCommands: claim.SurfaceCommands(),
		}); err != nil {
			c.log.Warn(logging.DestinationGeneral, "re-adoption: importing claim session failed; skipping",
				"slot", rec.SlotName, "err", err.Error())
			continue
		}
		sesID := security.ParseClaimIDStrict(rec.ClaimID).SecSessionID()

		// (b) Rebuild the slot's Claim.
		busy := strings.EqualFold(rec.Activity, "Busy")
		cl := claim.Adopt(claim.AdoptOptions{
			ClaimID:       rec.ClaimID,
			PublicClaimID: rec.PublicClaimID,
			SessionID:     sesID,
			ScheddAddr:    rec.ScheddAddr,
			ScheddName:    rec.ScheddName,
			User:          rec.User,
			ClientMachine: rec.ClientMachine,
			AliveInterval: rec.AliveInterval,
			Busy:          busy,
			LeaseDeadline: unixTime(rec.LeaseDeadline),
			Entered:       unixTime(rec.Entered),
		})
		s.SetClaim(cl)
		s.SetStateActivity("Claimed", activityOf(busy), unixTime(rec.Entered))
		adopted++
		c.log.Info(logging.DestinationGeneral, "re-adopted claim",
			"slot", rec.SlotName, "activity", activityOf(busy),
			"public_claim", rec.PublicClaimID, "schedd", rec.ScheddAddr,
			"starter_ip_addr", rec.StarterIpAddr)

		// (d) Resume the ALIVE lease loop (so the schedd never notices a fast
		// restart). A subsequent adopt-failure (starter gone) releases and cancels
		// it via the .exit-marker recovery.
		c.startAliveLoop(ctx, s)

		// (c) A Busy claim had a running starter: reconstruct its activation and
		// redial the surviving process-mode starter over its persisted socket.
		if busy && rec.StarterSocket != "" {
			var jobAd *classad.ClassAd
			if rec.JobAd != "" {
				if parsed, perr := classad.Parse(rec.JobAd); perr == nil {
					jobAd = parsed
				}
			}
			actx, cancel := context.WithCancel(ctx)
			c.activationGen++
			act := &activation{
				cancel:      cancel,
				gen:         c.activationGen,
				transport:   starter.NewUnixStartd(rec.StarterSocket),
				vacateCh:    make(chan int, 1),
				sandbox:     rec.Sandbox,
				jobAd:       jobAd,
				globalJID:   rec.GlobalJobID,
				starterAddr: rec.StarterIpAddr,
				starterPid:  rec.StarterPid,
				socketPath:  rec.StarterSocket,
				adopted:     true,
			}
			c.activations[rec.SlotName] = act
			go c.superviseStarter(actx, rec.SlotName, act, nil, true)
		}
	}
	// Refresh each re-adopted p-slot's ChildClaimIds now that every dslot's claim
	// is reconstructed.
	for _, p := range touchedParents {
		c.refreshPSlotChildren(p)
	}
	if adopted > 0 {
		c.log.Info(logging.DestinationGeneral, "re-adoption complete", "claims", adopted)
		c.reAdvertise(ctx)
	}
}

// reconstructDSlot recreates a dynamic slot from its persisted record during
// re-adoption: it carves the recorded resources out of the (config-rebuilt)
// parent p-slot and registers the dslot. The dslot's claim is reconstructed by
// the caller (doAdopt) right after. Returns nil if the parent no longer exists.
// Loop-only.
func (c *Core) reconstructDSlot(rec persist.Record) *slot.Slot {
	parent := c.byName[rec.ParentSlotName]
	if parent == nil {
		return nil
	}
	if existing := c.byName[rec.SlotName]; existing != nil {
		return existing // already reconstructed (idempotent)
	}
	res := slot.Resources{Cpus: rec.Cpus, MemoryMB: rec.MemoryMB, DiskKB: rec.DiskKB}
	d := slot.NewDynamicSlot(parent, rec.DSlotSubID, res, unixTime(rec.Entered))
	parent.Carve(res)
	c.addDSlot(d)
	if rec.DSlotSubID > c.dslotSeq {
		c.dslotSeq = rec.DSlotSubID
	}
	c.log.Info(logging.DestinationGeneral, "re-adoption: recreated dynamic slot from store",
		"dslot", d.Name, "parent", parent.Name, "cpus", res.Cpus, "remaining_cpus", parent.Resources().Cpus)
	return d
}

// doAdoptFailed handles a surviving-starter redial failure: read the sandbox
// .exit marker. If present, the job finished while the startd was down -- apply
// the terminal outcome and return the slot to Claimed/Idle. If absent, the
// starter is gone with the job's fate unknown: the claim is lost, so release it
// (which stops ALIVE) and let the schedd reschedule. Loop-only.
func (c *Core) doAdoptFailed(ctx context.Context, slotName string) {
	act := c.activations[slotName]
	if act == nil {
		return
	}
	s := c.byName[slotName]
	if s == nil {
		delete(c.activations, slotName)
		return
	}
	if m, ok := readExitMarker(act.sandbox); ok {
		c.log.Info(logging.DestinationGeneral,
			"re-adoption: surviving starter finished during downtime; applying recorded outcome",
			"slot", slotName, "status", m.WaitpidStatus, "reason", m.Reason)
		delete(c.activations, slotName)
		act.cancel()
		_ = act.transport.Close()
		if cl := s.Claim(); cl != nil && cl.State() == claim.ClaimedBusy {
			var finalAd *classad.ClassAd
			if m.FinalAd != "" {
				finalAd, _ = classad.Parse(m.FinalAd)
			}
			cl.SetFinal(finalAd, m.WaitpidStatus, m.Reason)
			now := time.Now()
			cl.SetIdle(now)
			s.SetStateActivity("Claimed", "Idle", now)
			c.persistSlot(s)
		}
		c.reAdvertise(ctx)
		return
	}
	// No marker: the job's outcome is unknown and the starter is gone. Treat the
	// claim as lost -- release it (mints a fresh id, stops ALIVE); the schedd's own
	// job lease will expire and reschedule.
	c.log.Warn(logging.DestinationGeneral,
		"re-adoption: surviving starter gone with no .exit marker; claim lost, releasing",
		"slot", slotName, "sandbox", act.sandbox)
	c.releaseSlot(ctx, s, "adopted starter lost (no exit marker)")
}

// readExitMarker reads and parses a sandbox .exit marker, if present.
func readExitMarker(sandbox string) (exitMarker, bool) {
	if sandbox == "" {
		return exitMarker{}, false
	}
	data, err := os.ReadFile(filepath.Join(sandbox, ".exit"))
	if err != nil {
		return exitMarker{}, false
	}
	var m exitMarker
	if err := json.Unmarshal(data, &m); err != nil {
		return exitMarker{}, false
	}
	return m, true
}

// unixTime converts a persisted unix-seconds value to a time.Time (zero for 0).
func unixTime(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

// activityOf maps the busy flag to the advertised Activity string.
func activityOf(busy bool) string {
	if busy {
		return "Busy"
	}
	return "Idle"
}
