// Package slot implements EP resource detection and the static-slot machine-ad
// machinery: it probes the host's Cpus/Memory/Disk (honoring the usual HTCondor
// config overrides), carves the total into NUM_SLOTS static slots, and builds
// the public and private ClassAds each slot advertises to the collector.
//
// The public-ad attribute set and the Requirements / WithinResourceLimits
// expressions mirror what a C++ condor_startd publishes for a static slot
// (src/condor_startd.V6/ResAttributes.cpp, Reqexp.cpp), so the negotiator and
// condor_status treat a Go-advertised slot exactly like a C++ one. Stage 1
// slots are Unclaimed/Idle and immutable after construction; the claim state
// machine (Stage 2+) will make them mutable, at which point the owning event
// loop becomes the single writer.
package slot

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/golang-htcondor/config"
	"golang.org/x/sys/unix"

	"github.com/bbockelm/golang-ep/internal/claim"
)

// withinResourceLimitsExpr is the WithinResourceLimits expression a C++ startd
// generates for a static slot with STARTD_JOB_HAS_REQUEST_ATTRS=false (the
// default), lifted verbatim (modulo whitespace) from
// MachAttributes::withinLimitsExpression (ResAttributes.cpp ~1920-1927, the
// climit_s form). It guards each resource with MY.<res> > 0 and requires the
// job's Request<res> to fit. CATALOG_SPACE is not modeled (Stage 1 has no
// catalog), so the plain "TARGET.RequestDisk <= MY.Disk" clause is used.
const withinResourceLimitsExpr = "MY.Cpus > 0 && TARGET.RequestCpus <= MY.Cpus && " +
	"MY.Memory > 0 && TARGET.RequestMemory <= MY.Memory && " +
	"MY.Disk > 0 && TARGET.RequestDisk <= MY.Disk"

// requirementsExpr is the machine Requirements a static slot advertises:
// START && WithinResourceLimits (Reqexp.cpp:193). It references the slot ad's
// own Start and WithinResourceLimits attributes.
const requirementsExpr = "Start && WithinResourceLimits"

// SlotType strings, matching the C++ startd's SlotType attribute values.
const (
	SlotTypeStatic        = "Static"
	SlotTypePartitionable = "Partitionable"
	SlotTypeDynamic       = "Dynamic"
)

// Resources holds a detected or per-slot resource quantity. Memory is in MB and
// Disk is in KB, matching the units the machine ad advertises.
type Resources struct {
	Cpus     int
	MemoryMB int64
	DiskKB   int64
}

// Platform is the set of host-identity attributes the slot ad advertises that a
// job's default Requirements and the negotiator match against. OpSys and Arch
// are LOAD-BEARING: the stock condor_submit default Requirements is
// (TARGET.Arch == "<arch>") && (TARGET.OpSys == "<opsys>") && ... so the slot
// MUST advertise the exact strings the pool's schedd/negotiator compute (e.g.
// on macOS 25.x: Arch="arm64", OpSys="macOS" -- NOT the Go runtime's "ARM64"/
// "OSX", which would silently no-match OpSys). These are resolved from the
// authoritative HTCondor config macros (ARCH/OPSYS/OPSYSANDVER/...) which C++
// condor computes identically, falling back to a Go mapping only when unset.
type Platform struct {
	OpSys            string
	Arch             string
	OpSysAndVer      string
	OpSysMajorVer    string
	UIDDomain        string
	FileSystemDomain string
}

// Slot is one static slot: its identity plus its share of the machine's
// resources and the machine-wide totals it also advertises. The identity and
// resource fields (Name, SlotID, Machine, Sinful, Res, Total, StartExpr,
// DaemonBorn) are fixed at construction; the claim state (State/Activity,
// Entered timestamps, the current claim, and the client identity advertised
// while claimed) is mutable from Stage 2 on.
//
// Stage 2 makes slots mutable: the startd event loop owns the transitions, but
// the collector query handler and the advertiser read slot ads from other
// goroutines, so all reads/writes of the mutable fields go through mu. The
// event loop is still the only WRITER; mu just makes the concurrent reads safe.
type Slot struct {
	Name       string // "slotN@host" (static/pslot) or "slotN_M@host" (dslot)
	SlotID     int    // N
	Machine    string // hostname
	Sinful     string // StartdIpAddr / MyAddress
	StartExpr  string // START config expression (default "TRUE")
	Plat       Platform
	Res        Resources
	Total      Resources // machine-wide totals (sum across slots)
	DaemonBorn int64     // DaemonStartTime (unix)

	// SlotType is "Static", "Partitionable" (a p-slot that carves dslots), or
	// "Dynamic" (a dslot carved from a p-slot). Fixed at construction.
	SlotType string
	// fullRes is a p-slot's ORIGINAL (undivided) resource allocation, advertised
	// as TotalSlot*; Res is the current REMAINING amount (fullRes minus every live
	// dslot's carve). For static/dynamic slots fullRes == Res.
	fullRes Resources
	// ParentName is a dslot's parent p-slot name (empty for static/pslots); SubID
	// is the dslot's _M suffix (the C++ r_sub_id). Both fixed at construction.
	ParentName string
	SubID      int

	// mu guards all mutable state below.
	mu       sync.Mutex
	state    string // "Unclaimed" / "Claimed"
	activity string // "Idle"
	entered  int64  // EnteredCurrentState / EnteredCurrentActivity (unix)
	claim    *claim.Claim
	// childClaimIDs is a p-slot's live dslot claim ids (advertised in the private
	// ad as ChildClaimIds; NumDynamicSlots is its length). Loop-updated.
	childClaimIDs []string
	// seq is this slot's UpdateSequenceNumber, bumped on each advertise.
	seq int64
}

// DetectResources probes the host for its total Cpus/Memory/Disk, honoring the
// standard HTCondor overrides: NUM_CPUS (Cpus), MEMORY in MB (Memory), and the
// EXECUTE directory's free space (Disk). Detection failures fall back to safe
// non-zero minimums so a slot is never advertised with a zero resource that
// would make WithinResourceLimits reject every job.
func DetectResources(cfg *config.Config) Resources {
	res := Resources{
		Cpus:     detectCpus(cfg),
		MemoryMB: detectMemoryMB(cfg),
		DiskKB:   detectDiskKB(ExecuteDir(cfg)),
	}
	if res.Cpus < 1 {
		res.Cpus = 1
	}
	if res.MemoryMB < 1 {
		res.MemoryMB = 1024
	}
	if res.DiskKB < 1 {
		res.DiskKB = 1024 * 1024 // 1 GB
	}
	return res
}

func detectCpus(cfg *config.Config) int {
	if v, ok := cfg.Get("NUM_CPUS"); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			return n
		}
	}
	return runtime.NumCPU()
}

// detectMemoryMB returns total physical memory in MB. MEMORY (config, in MB)
// overrides; otherwise it reads hw.memsize via sysctl on darwin and
// /proc/meminfo on linux.
func detectMemoryMB(cfg *config.Config) int64 {
	if v, ok := cfg.Get("MEMORY"); ok {
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil && n > 0 {
			return n
		}
	}
	if mb := detectPhysicalMemoryMB(); mb > 0 {
		return mb
	}
	return 0
}

// detectDiskKB returns the free space (KB) on the filesystem backing dir, via
// statfs. Mirrors the C++ startd advertising the EXECUTE dir's available blocks.
func detectDiskKB(dir string) int64 {
	if dir == "" {
		dir = os.TempDir()
	}
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		// Retry against a directory that certainly exists.
		if err := unix.Statfs(os.TempDir(), &st); err != nil {
			return 0
		}
	}
	// Bavail is blocks available to an unprivileged user; Bsize is the block
	// size in bytes. Both field names are shared across darwin and linux.
	return int64(st.Bavail) * int64(st.Bsize) / 1024
}

// ExecuteDir returns the EXECUTE directory (where job sandboxes are created and
// whose free space backs the Disk attribute), falling back to the system temp
// dir.
func ExecuteDir(cfg *config.Config) string {
	if v, ok := cfg.Get("EXECUTE"); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return os.TempDir()
}

// BuildSlots builds the startd's slot set from config: a single Partitionable
// slot owning all resources when partitionable mode is configured
// (SLOT_TYPE_1_PARTITIONABLE or EP_PARTITIONABLE_SLOT true), otherwise NUM_SLOTS
// static slots. It is the entry point cmd/startd/main uses; the static path
// delegates to BuildStaticSlots.
func BuildSlots(cfg *config.Config, hostname, sinful string, total Resources, now time.Time) []*Slot {
	if partitionableConfigured(cfg) {
		return []*Slot{BuildPartitionableSlot(cfg, hostname, sinful, total, now)}
	}
	return BuildStaticSlots(cfg, hostname, sinful, total, now)
}

// partitionableConfigured reports whether the config asks for a partitionable
// slot (the HTCondor SLOT_TYPE_1_PARTITIONABLE knob, or our EP_PARTITIONABLE_SLOT
// convenience knob).
func partitionableConfigured(cfg *config.Config) bool {
	for _, k := range []string{"SLOT_TYPE_1_PARTITIONABLE", "EP_PARTITIONABLE_SLOT"} {
		if v, ok := cfg.Get(k); ok {
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "true", "t", "yes", "1":
				return true
			}
		}
	}
	return false
}

// BuildPartitionableSlot builds ONE partitionable slot (slot1@host) owning the
// machine's full resources. It advertises PartitionableSlot=true and its full
// remaining resources; REQUEST_CLAIM carves dynamic slots out of it.
func BuildPartitionableSlot(cfg *config.Config, hostname, sinful string, total Resources, now time.Time) *Slot {
	startExpr := "TRUE"
	if v, ok := cfg.Get("START"); ok && strings.TrimSpace(v) != "" {
		startExpr = strings.TrimSpace(v)
	}
	entered := now.Unix()
	return &Slot{
		Name:       fmt.Sprintf("slot1@%s", hostname),
		SlotID:     1,
		Machine:    hostname,
		Sinful:     sinful,
		state:      "Unclaimed",
		activity:   "Idle",
		StartExpr:  startExpr,
		Plat:       resolvePlatform(cfg),
		Res:        total,
		fullRes:    total,
		Total:      total,
		SlotType:   SlotTypePartitionable,
		entered:    entered,
		DaemonBorn: entered,
	}
}

// NewDynamicSlot carves a dynamic slot (slotN_M@host) out of parent, taking res
// as its resources. The caller subtracts res from the parent (Carve) and mints
// the dslot its own claim; the dslot starts Unclaimed until Accept moves it to
// Claimed/Idle. now stamps the entry timestamps.
func NewDynamicSlot(parent *Slot, subID int, res Resources, now time.Time) *Slot {
	entered := now.Unix()
	return &Slot{
		Name:       fmt.Sprintf("slot%d_%d@%s", parent.SlotID, subID, parent.Machine),
		SlotID:     parent.SlotID,
		Machine:    parent.Machine,
		Sinful:     parent.Sinful,
		state:      "Unclaimed",
		activity:   "Idle",
		StartExpr:  parent.StartExpr,
		Plat:       parent.Plat,
		Res:        res,
		fullRes:    res,
		Total:      parent.Total,
		SlotType:   SlotTypeDynamic,
		ParentName: parent.Name,
		SubID:      subID,
		entered:    entered,
		DaemonBorn: parent.DaemonBorn,
	}
}

// IsPartitionable reports whether this is a p-slot (carves dynamic slots).
func (s *Slot) IsPartitionable() bool { return s.SlotType == SlotTypePartitionable }

// IsDynamic reports whether this is a dynamic slot carved from a p-slot.
func (s *Slot) IsDynamic() bool { return s.SlotType == SlotTypeDynamic }

// Resources returns a snapshot of the slot's current (remaining) resources.
func (s *Slot) Resources() Resources {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Res
}

// CanCarve reports whether req fits within the slot's current remaining
// resources (the resource half of WithinResourceLimits). Used to reject an
// over-budget dslot request against a partitionable slot.
func (s *Slot) CanCarve(req Resources) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return req.Cpus <= s.Res.Cpus && req.MemoryMB <= s.Res.MemoryMB && req.DiskKB <= s.Res.DiskKB
}

// Carve subtracts req from the slot's remaining resources (on dslot creation).
// Loop-only; guarded by mu for the concurrent advertise/query readers.
func (s *Slot) Carve(req Resources) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Res.Cpus -= req.Cpus
	s.Res.MemoryMB -= req.MemoryMB
	s.Res.DiskKB -= req.DiskKB
}

// Restore adds req back to the slot's remaining resources (on dslot destruction),
// clamped at the original full allocation. Loop-only.
func (s *Slot) Restore(req Resources) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Res.Cpus += req.Cpus
	s.Res.MemoryMB += req.MemoryMB
	s.Res.DiskKB += req.DiskKB
	if s.Res.Cpus > s.fullRes.Cpus {
		s.Res.Cpus = s.fullRes.Cpus
	}
	if s.Res.MemoryMB > s.fullRes.MemoryMB {
		s.Res.MemoryMB = s.fullRes.MemoryMB
	}
	if s.Res.DiskKB > s.fullRes.DiskKB {
		s.Res.DiskKB = s.fullRes.DiskKB
	}
}

// SetChildClaimIDs records a p-slot's live dslot claim ids (advertised in the
// private ad as ChildClaimIds/NumDynamicSlots). Loop-only.
func (s *Slot) SetChildClaimIDs(ids []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.childClaimIDs = ids
}

// BuildStaticSlots carves total into NUM_SLOTS (config, default 1) static slots
// named slotN@host, dividing each resource by integer division and handing the
// remainder to slot1 (so the whole machine is accounted for). now stamps
// EnteredCurrentState/Activity and DaemonStartTime.
func BuildStaticSlots(cfg *config.Config, hostname, sinful string, total Resources, now time.Time) []*Slot {
	n := 1
	if v, ok := cfg.Get("NUM_SLOTS"); ok {
		if parsed, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && parsed > 0 {
			n = parsed
		}
	}
	if n > total.Cpus && total.Cpus > 0 {
		// Never advertise more slots than Cpus (each static slot needs >=1 Cpu
		// or WithinResourceLimits rejects every job); clamp like the C++ startd.
		n = total.Cpus
	}

	startExpr := "TRUE"
	if v, ok := cfg.Get("START"); ok && strings.TrimSpace(v) != "" {
		startExpr = strings.TrimSpace(v)
	}

	plat := resolvePlatform(cfg)
	entered := now.Unix()
	shares := splitResources(total, n)
	slots := make([]*Slot, 0, n)
	for i := 0; i < n; i++ {
		id := i + 1
		slots = append(slots, &Slot{
			Name:       fmt.Sprintf("slot%d@%s", id, hostname),
			SlotID:     id,
			Machine:    hostname,
			Sinful:     sinful,
			state:      "Unclaimed",
			activity:   "Idle",
			StartExpr:  startExpr,
			Plat:       plat,
			Res:        shares[i],
			fullRes:    shares[i],
			Total:      total,
			SlotType:   SlotTypeStatic,
			entered:    entered,
			DaemonBorn: entered,
		})
	}
	return slots
}

// resolvePlatform reads the host-identity attributes from the HTCondor config's
// authoritative platform macros (the same ones a C++ startd publishes), falling
// back to a Go runtime mapping only when a macro is unset. Reading OPSYS/ARCH
// from config lets a Stage-5 harness inject the exact strings the local C++ pool
// computes (via condor_config_val), so the negotiator's OpSys/Arch equality
// tests in the default job Requirements match.
func resolvePlatform(cfg *config.Config) Platform {
	get := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := cfg.Get(k); ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
		return ""
	}
	p := Platform{
		OpSys:            get("OPSYS"),
		Arch:             get("ARCH"),
		OpSysAndVer:      get("OPSYSANDVER", "OPSYS_AND_VER"),
		OpSysMajorVer:    get("OPSYSMAJORVER", "OPSYS_MAJOR_VER"),
		UIDDomain:        get("UID_DOMAIN"),
		FileSystemDomain: get("FILESYSTEM_DOMAIN"),
	}
	if p.OpSys == "" {
		p.OpSys = goOSToHTCondorOS(runtime.GOOS)
	}
	if p.Arch == "" {
		p.Arch = goArchToHTCondorArch(runtime.GOARCH)
	}
	return p
}

// splitResources divides total into n shares by integer division, giving the
// remainder of each resource to the first share (slot1). Exported behavior is
// exercised by the unit tests.
func splitResources(total Resources, n int) []Resources {
	if n < 1 {
		n = 1
	}
	shares := make([]Resources, n)
	baseCpus := total.Cpus / n
	baseMem := total.MemoryMB / int64(n)
	baseDisk := total.DiskKB / int64(n)
	remCpus := total.Cpus - baseCpus*n
	remMem := total.MemoryMB - baseMem*int64(n)
	remDisk := total.DiskKB - baseDisk*int64(n)
	for i := 0; i < n; i++ {
		shares[i] = Resources{Cpus: baseCpus, MemoryMB: baseMem, DiskKB: baseDisk}
		if i == 0 {
			shares[i].Cpus += remCpus
			shares[i].MemoryMB += remMem
			shares[i].DiskKB += remDisk
		}
	}
	return shares
}

// PublicAd builds a fresh public machine ClassAd for the slot, stamping the
// current time (MyCurrentTime, EnteredCurrent*) and bumping the slot's
// UpdateSequenceNumber. Safe to call concurrently with the event loop's claim
// transitions (it takes the slot lock). The attribute set mirrors a C++
// static-slot machine ad closely enough for condor_status and the negotiator;
// a claimed slot additionally carries RemoteUser/RemoteOwner/ClientMachine/
// PublicClaimId and advertises Requirements=False so it never re-matches.
func (s *Slot) PublicAd() *classad.ClassAd {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	return s.buildAdLocked(true)
}

// MatchAd builds the slot's ad in its UNCLAIMED matching form: identical to
// PublicAd except Requirements is always the live "Start &&
// WithinResourceLimits" expression, never the literal False a claimed slot
// advertises. ACTIVATE_CLAIM re-evaluates the machine Requirements against the
// job ad (command.cpp:1831), and by then the slot is Claimed -- evaluating the
// advertised (claimed) ad would reject every job. This is the "requirements ad
// for matching" helper; it does not bump UpdateSequenceNumber (never
// advertised).
func (s *Slot) MatchAd() *classad.ClassAd {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buildAdLocked(false)
}

// buildAdLocked builds the slot's machine ad. claimedForm selects whether a
// claimed slot advertises Requirements=False (the advertised form,
// Reqexp.cpp:193) or keeps the unclaimed-form matching expression (MatchAd).
// Caller must hold mu.
func (s *Slot) buildAdLocked(claimedForm bool) *classad.ClassAd {
	now := time.Now().Unix()
	claimed := s.state == "Claimed"
	// A slot is "available" for matching only in Unclaimed/Owner; Matched,
	// Claimed and Preempting are unavailable and advertise Requirements=False so
	// the negotiator does not (double-)match them (Reqexp.cpp reqexp_unavail).
	available := s.state == "Unclaimed" || s.state == "Owner"
	ad := classad.New()

	_ = ad.Set("MyType", "Machine")
	_ = ad.Set("TargetType", "Job")
	_ = ad.Set("Name", s.Name)
	_ = ad.Set("Machine", s.Machine)
	_ = ad.Set("StartdIpAddr", s.Sinful)
	_ = ad.Set("MyAddress", s.Sinful)

	_ = ad.Set("State", s.state)
	_ = ad.Set("Activity", s.activity)
	_ = ad.Set("EnteredCurrentState", s.entered)
	_ = ad.Set("EnteredCurrentActivity", s.entered)

	// Per-slot resources.
	_ = ad.Set("Cpus", int64(s.Res.Cpus))
	_ = ad.Set("Memory", s.Res.MemoryMB)
	_ = ad.Set("Disk", s.Res.DiskKB)

	// Machine-wide totals and this slot's own totals. TotalSlot* is the slot's
	// FULL allocation (for a p-slot: its undivided size; for static/dynamic: its
	// resources), while Cpus/Memory/Disk above are the current remaining amount.
	_ = ad.Set("TotalCpus", int64(s.Total.Cpus))
	_ = ad.Set("TotalMemory", s.Total.MemoryMB)
	_ = ad.Set("TotalDisk", s.Total.DiskKB)
	_ = ad.Set("TotalSlotCpus", int64(s.fullRes.Cpus))
	_ = ad.Set("TotalSlotMemory", s.fullRes.MemoryMB)
	_ = ad.Set("TotalSlotDisk", s.fullRes.DiskKB)

	_ = ad.Set("SlotID", int64(s.SlotID))
	slotType := s.SlotType
	if slotType == "" {
		slotType = SlotTypeStatic
	}
	_ = ad.Set("SlotType", slotType)
	_ = ad.Set("SlotTypeID", int64(0))
	_ = ad.Set("SlotWeight", int64(s.Res.Cpus))
	// Partitionable/Dynamic markers the negotiator + condor_status key on.
	switch slotType {
	case SlotTypePartitionable:
		_ = ad.Set("PartitionableSlot", true)
		_ = ad.Set("NumDynamicSlots", int64(len(s.childClaimIDs)))
	case SlotTypeDynamic:
		_ = ad.Set("DynamicSlot", true)
		if s.ParentName != "" {
			_ = ad.Set("ParentSlotName", s.ParentName)
		}
		_ = ad.Set("DSlotId", int64(s.SubID))
	}

	// Policy expressions. Start / WithinResourceLimits are parsed so they are
	// real ClassAd expressions (not string literals); Requirements references
	// them by name, exactly like a C++ startd ad. A claimed slot advertises
	// Requirements=False so the negotiator never re-matches it (Reqexp.cpp:193).
	setExpr(ad, "Start", s.StartExpr)
	setExpr(ad, "WithinResourceLimits", withinResourceLimitsExpr)
	if !available && claimedForm {
		_ = ad.Set("Requirements", false)
	} else {
		setExpr(ad, "Requirements", requirementsExpr)
	}
	setExpr(ad, "Rank", "0.0")

	// File transfer + shared-FS identity. HasFileTransfer is LOAD-BEARING: the
	// stock condor_submit default job Requirements ends with
	// (TARGET.HasFileTransfer), so a slot that omits it never matches a vanilla
	// job. FileSystemDomain/UidDomain mirror the C++ startd ad (referenced by
	// same-FS job requirements and accounting).
	_ = ad.Set("HasFileTransfer", true)
	_ = ad.Set("HasFileTransferPluginMethods", "data,file")
	if s.Plat.FileSystemDomain != "" {
		_ = ad.Set("FileSystemDomain", s.Plat.FileSystemDomain)
	}
	if s.Plat.UIDDomain != "" {
		_ = ad.Set("UidDomain", s.Plat.UIDDomain)
	}

	// Claimed slots advertise the claiming client's identity (command.cpp).
	if claimed && s.claim != nil {
		if u := s.claim.User(); u != "" {
			_ = ad.Set("RemoteUser", u)
			_ = ad.Set("RemoteOwner", u)
		}
		if cm := s.claim.ClientMachine(); cm != "" {
			_ = ad.Set("ClientMachine", cm)
		}
		if pcid := s.claim.PublicClaimID(); pcid != "" {
			_ = ad.Set("PublicClaimId", pcid)
		}
	}

	// Load / activity metrics (static Stage-1 values).
	_ = ad.Set("CpuBusy", 0.0)
	_ = ad.Set("LoadAvg", 0.0)
	_ = ad.Set("TotalLoadAvg", 0.0)
	_ = ad.Set("TotalCondorLoadAvg", 0.0)
	_ = ad.Set("KeyboardIdle", int64(1<<30))
	_ = ad.Set("ConsoleIdle", int64(1<<30))
	_ = ad.Set("RetirementTimeRemaining", int64(0))
	_ = ad.Set("StartdSendsAlives", true)

	_ = ad.Set("OpSys", s.Plat.OpSys)
	_ = ad.Set("Arch", s.Plat.Arch)
	if s.Plat.OpSysAndVer != "" {
		_ = ad.Set("OpSysAndVer", s.Plat.OpSysAndVer)
	}
	if s.Plat.OpSysMajorVer != "" {
		if n, err := strconv.Atoi(s.Plat.OpSysMajorVer); err == nil {
			_ = ad.Set("OpSysMajorVer", int64(n))
		}
	}
	_ = ad.Set("CondorVersion", condorVersionString())
	_ = ad.Set("CondorPlatform", condorPlatformString())
	_ = ad.Set("DaemonStartTime", s.DaemonBorn)
	_ = ad.Set("MyCurrentTime", now)
	_ = ad.Set("UpdateSequenceNumber", s.seq)

	return ad
}

// PrivateAd builds the slot's private companion ad: the identity attributes the
// collector uses to pair it with the public ad, plus the slot's current (full,
// SECRET) claim id under both ClaimId and its legacy Capability alias. The
// advertise path serializes the private ad with PutClassAdIncludePrivate, so the
// secret survives the wire to the collector, which serves it only on the
// NEGOTIATOR-authorized QUERY_STARTD_PVT_ADS path -- exactly how the negotiator
// obtains the capability to hand a schedd.
func (s *Slot) PrivateAd() *classad.ClassAd {
	s.mu.Lock()
	defer s.mu.Unlock()

	ad := classad.New()
	_ = ad.Set("MyType", "Machine")
	_ = ad.Set("Name", s.Name)
	_ = ad.Set("StartdIpAddr", s.Sinful)
	_ = ad.Set("MyAddress", s.Sinful)
	if s.claim != nil {
		cid := s.claim.ClaimID()
		_ = ad.Set("ClaimId", cid)
		_ = ad.Set("Capability", cid)
	}
	// A p-slot's private ad carries its live dslot claim ids (ChildClaimIds, a
	// ClassAd list expression) and their count (NumDynamicSlots), mirroring
	// Resource::publish_private (Resource.cpp:3193). The negotiator uses these to
	// reason about the p-slot's committed children.
	if s.SlotType == SlotTypePartitionable {
		var sb strings.Builder
		sb.WriteByte('{')
		for i, id := range s.childClaimIDs {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(classad.Quote(id))
		}
		sb.WriteByte('}')
		if expr, err := classad.ParseExpr(sb.String()); err == nil {
			ad.InsertExpr("ChildClaimIds", expr)
		}
		_ = ad.Set("NumDynamicSlots", int64(len(s.childClaimIDs)))
	}
	return ad
}

// SetClaim installs a claim on the slot (the pre-minted Unclaimed claim at
// construction, and a fresh one after release). Caller must be the event loop.
func (s *Slot) SetClaim(c *claim.Claim) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claim = c
}

// Claim returns the slot's current claim (may be nil before priming).
func (s *Slot) Claim() *claim.Claim {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.claim
}

// State returns the slot's advertised State string ("Unclaimed"/"Claimed").
func (s *Slot) State() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Activity returns the slot's advertised Activity string.
func (s *Slot) Activity() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activity
}

// SetStateActivity updates the slot's State/Activity and stamps the
// EnteredCurrent* timestamp to now. Caller must be the event loop.
func (s *Slot) SetStateActivity(state, activity string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
	s.activity = activity
	s.entered = now.Unix()
}

// setExpr parses str as a ClassAd expression and inserts it under name. If it
// fails to parse (should not for our constant expressions), it falls back to
// inserting the raw string so the attribute is at least present.
func setExpr(ad *classad.ClassAd, name, str string) {
	if expr, err := classad.ParseExpr(str); err == nil {
		ad.InsertExpr(name, expr)
		return
	}
	_ = ad.Set(name, str)
}

func opSys() string { return goOSToHTCondorOS(runtime.GOOS) }
func arch() string  { return goArchToHTCondorArch(runtime.GOARCH) }

// goOSToHTCondorOS / goArchToHTCondorArch mirror the mapping in
// golang-htcondor/config (unexported there), so a Go EP advertises the same
// OpSys/Arch tokens a C++ startd would (linux->LINUX, darwin->OSX,
// amd64->X86_64, arm64->ARM64).
func goOSToHTCondorOS(goos string) string {
	switch goos {
	case "linux":
		return "LINUX"
	case "darwin":
		return "OSX"
	case "windows":
		return "WINDOWS"
	case "freebsd":
		return "FREEBSD"
	default:
		return strings.ToUpper(goos)
	}
}

func goArchToHTCondorArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "X86_64"
	case "386":
		return "INTEL"
	case "arm64":
		return "ARM64"
	case "arm":
		return "ARM"
	case "ppc64", "ppc64le":
		return "PPC64"
	case "s390x":
		return "S390X"
	default:
		return strings.ToUpper(goarch)
	}
}
