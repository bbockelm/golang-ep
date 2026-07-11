// Package persist implements the EP startd's durable claim store: a
// collections-backed, group-committed record of every slot's current claim,
// written at each claim-state transition so a restarted startd can re-adopt
// running work (Stage 7). Stage 6 wires the WRITE side (a record is committed
// on mint / matched / claimed / activated / released); the READ side
// (enumerate-and-redial re-adoption) is Stage 7, but List/Get are provided here
// and exercised by the reopen round-trip test so the Stage-7 read path is
// already proven to round-trip.
//
// Storage: one record per slot (keyed by slot name -- a slot holds at most one
// live claim, and each transition upserts that slot's current claim record).
// The backing store is a PelicanPlatform/classad/collections.Collection opened
// under <SPOOL>/ep/claims: each Put msyncs the dirtied memory-mapped segment
// pages before returning, so a committed record survives a crash without an
// explicit flush. The directory holds the FULL SECRET claim id (needed to
// re-register the match session and resume ALIVE after a restart), so it MUST
// be created 0700 under SPOOL, exactly as the C++ startd guards its spool.
package persist

import (
	"fmt"
	"os"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/collections"
)

// shards is the fixed shard count for the claim collection. It MUST stay
// constant across reopens (collections.Open recovers per-shard segment dirs and
// requires the same Shards count). A startd owns a handful of slots, so a single
// shard is plenty and keeps recovery trivial.
const shards = 1

// Record is one slot's persisted claim state: everything a restarted startd
// needs to reconstruct the claim, re-register its match session, resume the
// ALIVE lease, and redial the (process-mode) starter. Fields that are only
// meaningful once a job is activated (JobAd, StarterPid, ...) are zero/empty
// otherwise.
type Record struct {
	// SlotName is the collection key: "slotN@host".
	SlotName string
	// ClaimID is the FULL SECRET claim id (capability). Load-bearing for Stage-7
	// session re-registration + ALIVE resumption; never log it verbatim.
	ClaimID string
	// PublicClaimID is the secret-elided form, safe for logs/CA_LOCATE_STARTER.
	PublicClaimID string
	// State / Activity are the advertised slot state ("Unclaimed"/"Claimed",
	// "Idle"/"Busy") at commit time.
	State    string
	Activity string
	// SlotType is "Static", "Partitionable", or "Dynamic". Empty is treated as
	// Static on read (backward compatible with pre-Stage-8 records).
	SlotType string
	// Dynamic-slot re-adoption fields (Stage 8): the parent p-slot name and the
	// resources carved from it (so a restarted startd can recreate the dslot and
	// subtract from the rebuilt parent), plus the _M sub-id.
	ParentSlotName string
	DSlotSubID     int
	Cpus           int
	MemoryMB       int64
	DiskKB         int64
	// Schedd lease bookkeeping (populated once Claimed).
	ScheddAddr    string
	ScheddName    string
	User          string
	ClientMachine string
	AliveInterval int
	// LeaseDeadline / Entered are unix seconds (0 when unset).
	LeaseDeadline int64
	Entered       int64
	// JobAd is the activated job ad serialized as a new-ClassAd string (empty
	// until an ACTIVATE_CLAIM is accepted). Stored with private attributes so a
	// re-adopting startd has the authoritative ad.
	JobAd string
	// GlobalJobID is the activated job's GlobalJobId (empty until activation).
	// CA_LOCATE_STARTER matches a reconnecting shadow's request against it.
	GlobalJobID string
	// Starter linkage (process mode; populated once a starter is spawned).
	StarterPid int
	// StarterSocket is the per-claim Unix control socket path a restarted startd
	// redials to re-adopt the (surviving) process starter.
	StarterSocket string
	// StarterIpAddr is the process starter's own CA_CMD command sinful, learned
	// from its Hello. CA_LOCATE_STARTER answers a reconnecting shadow with it
	// (even before the starter re-Hellos, since it survives in the store).
	StarterIpAddr string
	Sandbox       string
}

// attribute names for the on-disk ClassAd form. Kept local to this package so
// the persisted schema is a single source of truth.
const (
	attrSlotName      = "SlotName"
	attrClaimID       = "ClaimId"
	attrPublicClaimID = "PublicClaimId"
	attrState         = "State"
	attrActivity      = "Activity"
	attrScheddAddr    = "ScheddAddr"
	attrScheddName    = "ScheddName"
	attrUser          = "RemoteUser"
	attrClientMachine = "ClientMachine"
	attrAliveInterval = "AliveInterval"
	attrLeaseDeadline = "LeaseDeadline"
	attrEntered       = "EnteredCurrentState"
	attrJobAd         = "JobAd"
	attrGlobalJobID   = "GlobalJobId"
	attrStarterPid    = "StarterPid"
	attrStarterSocket = "StarterSocket"
	attrStarterIPAddr = "StarterIpAddr"
	attrSandbox       = "Sandbox"
	attrSlotType      = "SlotType"
	attrParentSlot    = "ParentSlotName"
	attrDSlotSubID    = "DSlotId"
	attrCpus          = "Cpus"
	attrMemoryMB      = "Memory"
	attrDiskKB        = "Disk"
)

// toAd serializes a Record to the ClassAd stored in the collection.
func (r *Record) toAd() *classad.ClassAd {
	ad := classad.New()
	_ = ad.Set(attrSlotName, r.SlotName)
	_ = ad.Set(attrClaimID, r.ClaimID)
	_ = ad.Set(attrPublicClaimID, r.PublicClaimID)
	_ = ad.Set(attrState, r.State)
	_ = ad.Set(attrActivity, r.Activity)
	_ = ad.Set(attrScheddAddr, r.ScheddAddr)
	_ = ad.Set(attrScheddName, r.ScheddName)
	_ = ad.Set(attrUser, r.User)
	_ = ad.Set(attrClientMachine, r.ClientMachine)
	_ = ad.Set(attrAliveInterval, int64(r.AliveInterval))
	_ = ad.Set(attrLeaseDeadline, r.LeaseDeadline)
	_ = ad.Set(attrEntered, r.Entered)
	if r.JobAd != "" {
		_ = ad.Set(attrJobAd, r.JobAd)
	}
	_ = ad.Set(attrGlobalJobID, r.GlobalJobID)
	_ = ad.Set(attrStarterPid, int64(r.StarterPid))
	_ = ad.Set(attrStarterSocket, r.StarterSocket)
	_ = ad.Set(attrStarterIPAddr, r.StarterIpAddr)
	_ = ad.Set(attrSandbox, r.Sandbox)
	if r.SlotType != "" {
		_ = ad.Set(attrSlotType, r.SlotType)
	}
	if r.ParentSlotName != "" {
		_ = ad.Set(attrParentSlot, r.ParentSlotName)
		_ = ad.Set(attrDSlotSubID, int64(r.DSlotSubID))
		_ = ad.Set(attrCpus, int64(r.Cpus))
		_ = ad.Set(attrMemoryMB, r.MemoryMB)
		_ = ad.Set(attrDiskKB, r.DiskKB)
	}
	return ad
}

// recordFromAd deserializes a stored ClassAd back to a Record.
func recordFromAd(ad *classad.ClassAd) Record {
	var r Record
	r.SlotName, _ = ad.EvaluateAttrString(attrSlotName)
	r.ClaimID, _ = ad.EvaluateAttrString(attrClaimID)
	r.PublicClaimID, _ = ad.EvaluateAttrString(attrPublicClaimID)
	r.State, _ = ad.EvaluateAttrString(attrState)
	r.Activity, _ = ad.EvaluateAttrString(attrActivity)
	r.ScheddAddr, _ = ad.EvaluateAttrString(attrScheddAddr)
	r.ScheddName, _ = ad.EvaluateAttrString(attrScheddName)
	r.User, _ = ad.EvaluateAttrString(attrUser)
	r.ClientMachine, _ = ad.EvaluateAttrString(attrClientMachine)
	if v, ok := ad.EvaluateAttrInt(attrAliveInterval); ok {
		r.AliveInterval = int(v)
	}
	if v, ok := ad.EvaluateAttrInt(attrLeaseDeadline); ok {
		r.LeaseDeadline = v
	}
	if v, ok := ad.EvaluateAttrInt(attrEntered); ok {
		r.Entered = v
	}
	r.JobAd, _ = ad.EvaluateAttrString(attrJobAd)
	r.GlobalJobID, _ = ad.EvaluateAttrString(attrGlobalJobID)
	if v, ok := ad.EvaluateAttrInt(attrStarterPid); ok {
		r.StarterPid = int(v)
	}
	r.StarterSocket, _ = ad.EvaluateAttrString(attrStarterSocket)
	r.StarterIpAddr, _ = ad.EvaluateAttrString(attrStarterIPAddr)
	r.Sandbox, _ = ad.EvaluateAttrString(attrSandbox)
	r.SlotType, _ = ad.EvaluateAttrString(attrSlotType)
	r.ParentSlotName, _ = ad.EvaluateAttrString(attrParentSlot)
	if v, ok := ad.EvaluateAttrInt(attrDSlotSubID); ok {
		r.DSlotSubID = int(v)
	}
	if v, ok := ad.EvaluateAttrInt(attrCpus); ok {
		r.Cpus = int(v)
	}
	if v, ok := ad.EvaluateAttrInt(attrMemoryMB); ok {
		r.MemoryMB = v
	}
	if v, ok := ad.EvaluateAttrInt(attrDiskKB); ok {
		r.DiskKB = v
	}
	return r
}

// Store is the durable claim collection. It is safe for use from the startd's
// single-writer event loop; the underlying collection is itself concurrency
// safe, but the EP only writes from the loop.
type Store struct {
	coll *collections.Collection
	dir  string
}

// Open opens (creating if absent) the claim store rooted at dir. The directory
// and its parents are created 0700 first -- it holds secret claim ids. The same
// call both creates a fresh store and reopens/recovers an existing one (the
// collections layer replays its memory-mapped segments), so Stage-7 re-adoption
// uses this exact entry point.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("persist: empty claims directory")
	}
	// 0700: the store holds full secret claim ids.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("persist: creating claims dir %s: %w", dir, err)
	}
	coll, err := collections.Open(collections.Options{
		Dir:    dir,
		Shards: shards,
	})
	if err != nil {
		return nil, fmt.Errorf("persist: opening claims collection at %s: %w", dir, err)
	}
	return &Store{coll: coll, dir: dir}, nil
}

// Dir returns the store's on-disk directory.
func (s *Store) Dir() string { return s.dir }

// Put commits one slot's claim record (durable on return: the collection msyncs
// the dirtied segment pages before Put returns). Called on every claim-state
// transition. A zero-value SlotName is rejected -- the slot name is the key.
func (s *Store) Put(r Record) error {
	if r.SlotName == "" {
		return fmt.Errorf("persist: record has empty SlotName (the store key)")
	}
	if err := s.coll.Put([]byte(r.SlotName), r.toAd()); err != nil {
		return fmt.Errorf("persist: committing claim record for %s: %w", r.SlotName, err)
	}
	return nil
}

// Get returns the persisted record for a slot, or ok=false if none is stored.
func (s *Store) Get(slotName string) (Record, bool) {
	ad, ok := s.coll.Get([]byte(slotName))
	if !ok {
		return Record{}, false
	}
	return recordFromAd(ad), true
}

// Delete removes a slot's persisted record (e.g. a claim gone for good). Safe if
// no record exists.
func (s *Store) Delete(slotName string) {
	s.coll.Delete([]byte(slotName))
}

// List returns every persisted claim record. Stage-7 re-adoption enumerates
// these on startup to reconstruct claimed slots and redial their starters.
func (s *Store) List() []Record {
	var out []Record
	for ad := range s.coll.Scan() {
		out = append(out, recordFromAd(ad))
	}
	return out
}

// Close flushes and unmaps the collection. The store is unusable afterward.
func (s *Store) Close() error {
	if s.coll == nil {
		return nil
	}
	return s.coll.Close()
}
