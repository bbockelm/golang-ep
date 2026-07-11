package slot

import (
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/config"
)

func mustCfg(t *testing.T, body string) *config.Config {
	t.Helper()
	cfg, err := config.NewFromReader(strings.NewReader(body))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

// TestBuildPartitionableSlot verifies the partitionable-slot builder and its ad.
func TestBuildPartitionableSlot(t *testing.T) {
	cfg := mustCfg(t, "SLOT_TYPE_1_PARTITIONABLE=true\nSTART=TRUE\n")
	total := Resources{Cpus: 4, MemoryMB: 4096, DiskKB: 400000}
	slots := BuildSlots(cfg, "host", "<127.0.0.1:9?sock=s>", total, time.Now())
	if len(slots) != 1 {
		t.Fatalf("partitionable config built %d slots, want 1", len(slots))
	}
	ps := slots[0]
	if !ps.IsPartitionable() {
		t.Fatalf("slot is not partitionable: type=%q", ps.SlotType)
	}
	if ps.Name != "slot1@host" {
		t.Errorf("p-slot name = %q, want slot1@host", ps.Name)
	}
	if ps.Resources() != total {
		t.Errorf("p-slot resources = %+v, want full %+v", ps.Resources(), total)
	}
	ad := ps.PublicAd()
	if v, _ := ad.EvaluateAttrBool("PartitionableSlot"); !v {
		t.Error("public ad missing PartitionableSlot=true")
	}
	if v, _ := ad.EvaluateAttrString("SlotType"); v != SlotTypePartitionable {
		t.Errorf("SlotType = %q, want Partitionable", v)
	}
	// Non-partitionable config builds static slots.
	stat := BuildSlots(mustCfg(t, "NUM_SLOTS=2\n"), "host", "<x>", total, time.Now())
	if len(stat) != 2 || stat[0].IsPartitionable() {
		t.Errorf("static config built %d slots (partitionable=%v)", len(stat), stat[0].IsPartitionable())
	}
}

// TestCarveRestoreMath exercises the resource carve/restore arithmetic and the
// over-budget CanCarve guard.
func TestCarveRestoreMath(t *testing.T) {
	cfg := mustCfg(t, "SLOT_TYPE_1_PARTITIONABLE=true\n")
	total := Resources{Cpus: 4, MemoryMB: 4096, DiskKB: 400000}
	ps := BuildPartitionableSlot(cfg, "host", "<x>", total, time.Now())

	req := Resources{Cpus: 1, MemoryMB: 1024, DiskKB: 100000}
	if !ps.CanCarve(req) {
		t.Fatal("CanCarve rejected a request that fits")
	}
	ps.Carve(req)
	if got := ps.Resources(); got.Cpus != 3 || got.MemoryMB != 3072 || got.DiskKB != 300000 {
		t.Fatalf("after one carve: %+v, want {3 3072 300000}", got)
	}
	// Carve twice more (three 1-cpu dslots -> 1 cpu left).
	ps.Carve(req)
	ps.Carve(req)
	if got := ps.Resources(); got.Cpus != 1 {
		t.Fatalf("after three carves Cpus = %d, want 1", got.Cpus)
	}
	// A fourth 1-cpu carve still fits (1 cpu left), but a 2-cpu request does not.
	if !ps.CanCarve(req) {
		t.Error("CanCarve rejected the 4th 1-cpu request (1 cpu remained)")
	}
	big := Resources{Cpus: 2, MemoryMB: 1024, DiskKB: 1000}
	if ps.CanCarve(big) {
		t.Error("CanCarve accepted an over-budget (2-cpu) request with 1 cpu left")
	}
	// Restore two dslots; resources climb back, clamped at the full allocation.
	ps.Restore(req)
	ps.Restore(req)
	if got := ps.Resources(); got.Cpus != 3 {
		t.Fatalf("after restoring 2 of 3: Cpus = %d, want 3", got.Cpus)
	}
	// Over-restore is clamped at fullRes (never exceeds the original total).
	ps.Restore(req)
	ps.Restore(req)
	ps.Restore(req)
	if got := ps.Resources(); got != total {
		t.Fatalf("after over-restore: %+v, want clamped %+v", got, total)
	}
}

// TestNewDynamicSlot verifies dslot naming, type, and ad markers.
func TestNewDynamicSlot(t *testing.T) {
	cfg := mustCfg(t, "SLOT_TYPE_1_PARTITIONABLE=true\n")
	total := Resources{Cpus: 4, MemoryMB: 4096, DiskKB: 400000}
	ps := BuildPartitionableSlot(cfg, "host", "<x>", total, time.Now())
	req := Resources{Cpus: 1, MemoryMB: 1024, DiskKB: 100000}
	d := NewDynamicSlot(ps, 1, req, time.Now())
	if d.Name != "slot1_1@host" {
		t.Errorf("dslot name = %q, want slot1_1@host", d.Name)
	}
	if !d.IsDynamic() {
		t.Errorf("dslot type = %q, want Dynamic", d.SlotType)
	}
	if d.ParentName != "slot1@host" {
		t.Errorf("dslot ParentName = %q, want slot1@host", d.ParentName)
	}
	if d.Resources() != req {
		t.Errorf("dslot resources = %+v, want %+v", d.Resources(), req)
	}
	ad := d.PublicAd()
	if v, _ := ad.EvaluateAttrBool("DynamicSlot"); !v {
		t.Error("dslot public ad missing DynamicSlot=true")
	}
	if v, _ := ad.EvaluateAttrInt("Cpus"); v != 1 {
		t.Errorf("dslot Cpus = %d, want 1", v)
	}
}

// TestPSlotChildClaimIDs checks the private-ad ChildClaimIds list + NumDynamicSlots.
func TestPSlotChildClaimIDs(t *testing.T) {
	cfg := mustCfg(t, "SLOT_TYPE_1_PARTITIONABLE=true\n")
	total := Resources{Cpus: 4, MemoryMB: 4096, DiskKB: 400000}
	ps := BuildPartitionableSlot(cfg, "host", "<x>", total, time.Now())
	ps.SetChildClaimIDs([]string{"<a>#1#2#k1", "<b>#3#4#k2"})
	priv := ps.PrivateAd()
	if v, _ := priv.EvaluateAttrInt("NumDynamicSlots"); v != 2 {
		t.Errorf("NumDynamicSlots = %d, want 2", v)
	}
	expr, ok := priv.Lookup("ChildClaimIds")
	if !ok || expr == nil {
		t.Fatal("private ad missing ChildClaimIds")
	}
	s := expr.String()
	if !strings.Contains(s, "k1") || !strings.Contains(s, "k2") {
		t.Errorf("ChildClaimIds = %q, want a list containing both child ids", s)
	}
}
