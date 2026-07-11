// Package advertise pushes the EP's per-slot machine ads to the pool's
// collector(s). Each round sends, for every slot, a public+private ad pair on
// one CEDAR message (UPDATE_STARTD_AD), using golang-htcondor's
// AdvertiseOptions.PrivateAd so the private half rides the same wire the C++
// startd uses (dc_collector.cpp: putClassAd(public) then putClassAd(private)).
// On shutdown it sends INVALIDATE_STARTD_ADS query ads so a slot disappears
// from condor_status immediately rather than waiting for its classad to expire.
//
// Advertise/Invalidate are always called from the startd core's single-writer
// event loop, so the Advertiser needs no internal locking.
package advertise

import (
	"context"
	"fmt"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"

	"github.com/bbockelm/golang-ep/internal/slot"
)

// Advertiser builds and sends the per-slot machine ads.
type Advertiser struct {
	log *logging.Logger
	// collectorsFn resolves the collector endpoints fresh each round (the
	// collector's address file may not exist at first boot, and a collector
	// restart under shared port can change its ephemeral port).
	collectorsFn func() []string
	// slotsFn returns the slots to advertise (immutable in Stage 1; a func so
	// later stages can hand back the live slot set).
	slotsFn func() []*slot.Slot
}

// Options configures a new Advertiser.
type Options struct {
	Logger       *logging.Logger
	CollectorsFn func() []string
	SlotsFn      func() []*slot.Slot
}

// New builds an Advertiser.
func New(opts Options) *Advertiser {
	return &Advertiser{
		log:          opts.Logger,
		collectorsFn: opts.CollectorsFn,
		slotsFn:      opts.SlotsFn,
	}
}

// Advertise sends every slot's public+private ad pair to every configured
// collector. Per-collector and per-slot failures are logged but never abort the
// round: a transient collector outage should not wedge the EP.
func (a *Advertiser) Advertise(ctx context.Context) {
	addrs := a.collectors()
	if len(addrs) == 0 {
		a.log.Warn(logging.DestinationGeneral,
			"no collector address resolved yet (COLLECTOR_HOST unset/port 0 and no address file); skipping startd ad update")
		return
	}
	slots := a.slots()
	for _, s := range slots {
		pub := s.PublicAd()
		priv := s.PrivateAd()
		// Command is left zero so it derives from MyType="Machine"
		// (UPDATE_STARTD_AD); PrivateAd rides the same message.
		opts := &htcondor.AdvertiseOptions{UseTCP: true, PrivateAd: priv}
		for _, addr := range addrs {
			col := htcondor.NewCollector(addr)
			if err := col.Advertise(ctx, pub, opts); err != nil {
				a.log.Warn(logging.DestinationGeneral, "startd ad update failed",
					"collector", addr, "slot", s.Name, "err", err.Error())
				continue
			}
			a.log.Debug(logging.DestinationGeneral, "sent startd ad",
				"collector", addr, "slot", s.Name, "state", s.State())
		}
	}
}

// Invalidate sends an INVALIDATE_STARTD_ADS query ad for every slot so the
// collector drops the slot's ads on a clean shutdown. Best-effort.
func (a *Advertiser) Invalidate(ctx context.Context) {
	addrs := a.collectors()
	if len(addrs) == 0 {
		return
	}
	opts := &htcondor.AdvertiseOptions{UseTCP: true, Command: commands.INVALIDATE_STARTD_ADS}
	for _, s := range a.slots() {
		ad := invalidateAd(s)
		for _, addr := range addrs {
			col := htcondor.NewCollector(addr)
			if err := col.Advertise(ctx, ad, opts); err != nil {
				a.log.Warn(logging.DestinationGeneral, "startd ad invalidate failed",
					"collector", addr, "slot", s.Name, "err", err.Error())
				continue
			}
			a.log.Debug(logging.DestinationGeneral, "invalidated startd ad",
				"collector", addr, "slot", s.Name)
		}
	}
}

// InvalidateSlot sends an INVALIDATE_STARTD_ADS query ad for a single slot so
// the collector drops it immediately (used when a dynamic slot is destroyed and
// its resources return to the parent p-slot). Best-effort.
func (a *Advertiser) InvalidateSlot(ctx context.Context, s *slot.Slot) {
	addrs := a.collectors()
	if len(addrs) == 0 || s == nil {
		return
	}
	opts := &htcondor.AdvertiseOptions{UseTCP: true, Command: commands.INVALIDATE_STARTD_ADS}
	ad := invalidateAd(s)
	for _, addr := range addrs {
		col := htcondor.NewCollector(addr)
		if err := col.Advertise(ctx, ad, opts); err != nil {
			a.log.Warn(logging.DestinationGeneral, "startd dslot invalidate failed",
				"collector", addr, "slot", s.Name, "err", err.Error())
			continue
		}
		a.log.Debug(logging.DestinationGeneral, "invalidated destroyed dslot ad",
			"collector", addr, "slot", s.Name)
	}
}

// invalidateAd builds the query ad that removes one slot: MyType="Query",
// TargetType="Machine", Requirements matching the slot's Name, plus Name and
// MyAddress so a key-based collector can also match it. Mirrors the C++ startd's
// invalidate ad.
func invalidateAd(s *slot.Slot) *classad.ClassAd {
	ad := classad.New()
	_ = ad.Set("MyType", "Query")
	_ = ad.Set("TargetType", "Machine")
	if expr, err := classad.ParseExpr(fmt.Sprintf("Name == %s", classad.Quote(s.Name))); err == nil {
		ad.InsertExpr("Requirements", expr)
	} else {
		_ = ad.Set("Requirements", true)
	}
	_ = ad.Set("Name", s.Name)
	_ = ad.Set("MyAddress", s.Sinful)
	return ad
}

func (a *Advertiser) collectors() []string {
	if a.collectorsFn == nil {
		return nil
	}
	return a.collectorsFn()
}

func (a *Advertiser) slots() []*slot.Slot {
	if a.slotsFn == nil {
		return nil
	}
	return a.slotsFn()
}
