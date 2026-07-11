package slot

import (
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// TestSplitResourcesEven checks an evenly divisible split.
func TestSplitResourcesEven(t *testing.T) {
	total := Resources{Cpus: 8, MemoryMB: 8000, DiskKB: 8000}
	shares := splitResources(total, 2)
	if len(shares) != 2 {
		t.Fatalf("expected 2 shares, got %d", len(shares))
	}
	for i, s := range shares {
		if s.Cpus != 4 || s.MemoryMB != 4000 || s.DiskKB != 4000 {
			t.Errorf("share %d = %+v, want 4/4000/4000", i, s)
		}
	}
}

// TestSplitResourcesRemainderToSlot1 checks the remainder lands on the first
// share (slot1).
func TestSplitResourcesRemainderToSlot1(t *testing.T) {
	total := Resources{Cpus: 7, MemoryMB: 1001, DiskKB: 10}
	shares := splitResources(total, 2)
	// 7/2 = 3 base, remainder 1 -> slot1 = 4, slot2 = 3.
	if shares[0].Cpus != 4 || shares[1].Cpus != 3 {
		t.Errorf("cpus = %d/%d, want 4/3", shares[0].Cpus, shares[1].Cpus)
	}
	// 1001/2 = 500 base, remainder 1 -> 501/500.
	if shares[0].MemoryMB != 501 || shares[1].MemoryMB != 500 {
		t.Errorf("memory = %d/%d, want 501/500", shares[0].MemoryMB, shares[1].MemoryMB)
	}
	// 10/2 = 5 base, remainder 0 -> 5/5.
	if shares[0].DiskKB != 5 || shares[1].DiskKB != 5 {
		t.Errorf("disk = %d/%d, want 5/5", shares[0].DiskKB, shares[1].DiskKB)
	}
	// The split conserves the total.
	var sumC int
	var sumM, sumD int64
	for _, s := range shares {
		sumC += s.Cpus
		sumM += s.MemoryMB
		sumD += s.DiskKB
	}
	if sumC != total.Cpus || sumM != total.MemoryMB || sumD != total.DiskKB {
		t.Errorf("split did not conserve total: got %d/%d/%d", sumC, sumM, sumD)
	}
}

// buildTestSlots builds slots directly (no config) for ad-content assertions.
func buildTestSlots(t *testing.T, n int, total Resources) []*Slot {
	t.Helper()
	shares := splitResources(total, n)
	now := time.Now().Unix()
	slots := make([]*Slot, 0, n)
	for i := 0; i < n; i++ {
		slots = append(slots, &Slot{
			Name:       "slot" + itoa(i+1) + "@testhost",
			SlotID:     i + 1,
			Machine:    "testhost",
			Sinful:     "<127.0.0.1:12345?sock=startd>",
			state:      "Unclaimed",
			activity:   "Idle",
			StartExpr:  "TRUE",
			Plat:       Platform{OpSys: opSys(), Arch: arch()},
			Res:        shares[i],
			fullRes:    shares[i],
			Total:      total,
			SlotType:   SlotTypeStatic,
			entered:    now,
			DaemonBorn: now,
		})
	}
	return slots
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

// TestPublicAdContent checks the public ad carries the required attributes with
// the right types/values.
func TestPublicAdContent(t *testing.T) {
	slots := buildTestSlots(t, 2, Resources{Cpus: 4, MemoryMB: 8000, DiskKB: 100000})
	ad := slots[0].PublicAd()

	wantStr := map[string]string{
		"MyType":       "Machine",
		"TargetType":   "Job",
		"Name":         "slot1@testhost",
		"Machine":      "testhost",
		"State":        "Unclaimed",
		"Activity":     "Idle",
		"SlotType":     "Static",
		"StartdIpAddr": "<127.0.0.1:12345?sock=startd>",
		"MyAddress":    "<127.0.0.1:12345?sock=startd>",
	}
	for k, want := range wantStr {
		if got, ok := ad.EvaluateAttrString(k); !ok || got != want {
			t.Errorf("%s = %q (ok=%v), want %q", k, got, ok, want)
		}
	}

	wantInt := map[string]int64{
		"Cpus":            2, // 4 split across 2 slots
		"Memory":          4000,
		"TotalCpus":       4,
		"TotalMemory":     8000,
		"TotalSlotCpus":   2,
		"TotalSlotMemory": 4000,
		"SlotID":          1,
		"SlotWeight":      2,
	}
	for k, want := range wantInt {
		if got, ok := ad.EvaluateAttrInt(k); !ok || got != want {
			t.Errorf("%s = %d (ok=%v), want %d", k, got, ok, want)
		}
	}

	if b, ok := ad.EvaluateAttrBool("StartdSendsAlives"); !ok || !b {
		t.Errorf("StartdSendsAlives = %v (ok=%v), want true", b, ok)
	}

	// OpSys/Arch must be present (values depend on the build host).
	if v, ok := ad.EvaluateAttrString("OpSys"); !ok || v == "" {
		t.Errorf("OpSys missing")
	}
	if v, ok := ad.EvaluateAttrString("Arch"); !ok || v == "" {
		t.Errorf("Arch missing")
	}

	// UpdateSequenceNumber must bump between advertise rounds.
	seq1, _ := ad.EvaluateAttrInt("UpdateSequenceNumber")
	ad2 := slots[0].PublicAd()
	seq2, _ := ad2.EvaluateAttrInt("UpdateSequenceNumber")
	if seq2 <= seq1 {
		t.Errorf("UpdateSequenceNumber did not increase: %d -> %d", seq1, seq2)
	}
}

// TestRequirementsIsExpression verifies Requirements/Start/WithinResourceLimits
// are real ClassAd expressions (not string literals) that evaluate to booleans.
func TestRequirementsIsExpression(t *testing.T) {
	slots := buildTestSlots(t, 1, Resources{Cpus: 4, MemoryMB: 8000, DiskKB: 100000})
	ad := slots[0].PublicAd()

	// With no target job, Start (TRUE) evaluates true; WithinResourceLimits
	// references TARGET.Request* which is undefined -> not a plain bool, so
	// Requirements should be undefined/false. Set a fitting target and re-check.
	job := classad.New()
	_ = job.Set("RequestCpus", int64(1))
	_ = job.Set("RequestMemory", int64(1024))
	_ = job.Set("RequestDisk", int64(1024))
	ad.SetTarget(job)

	if v, ok := ad.EvaluateAttrBool("WithinResourceLimits"); !ok || !v {
		t.Errorf("WithinResourceLimits with a fitting job = %v (ok=%v), want true", v, ok)
	}
	if v, ok := ad.EvaluateAttrBool("Requirements"); !ok || !v {
		t.Errorf("Requirements with a fitting job = %v (ok=%v), want true", v, ok)
	}
}

// TestWithinResourceLimitsFit exercises the WithinResourceLimits expression
// against fitting and non-fitting job ads.
func TestWithinResourceLimitsFit(t *testing.T) {
	slots := buildTestSlots(t, 1, Resources{Cpus: 4, MemoryMB: 8000, DiskKB: 100000})

	cases := []struct {
		name                     string
		reqCpus, reqMem, reqDisk int64
		want                     bool
	}{
		{"fits exactly", 4, 8000, 100000, true},
		{"fits well under", 1, 512, 1024, true},
		{"too many cpus", 5, 512, 1024, false},
		{"too much memory", 1, 9000, 1024, false},
		{"too much disk", 1, 512, 200000, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ad := slots[0].PublicAd()
			job := classad.New()
			_ = job.Set("RequestCpus", tc.reqCpus)
			_ = job.Set("RequestMemory", tc.reqMem)
			_ = job.Set("RequestDisk", tc.reqDisk)
			ad.SetTarget(job)
			got, ok := ad.EvaluateAttrBool("WithinResourceLimits")
			if !ok {
				t.Fatalf("WithinResourceLimits did not evaluate to a bool")
			}
			if got != tc.want {
				t.Errorf("WithinResourceLimits = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPrivateAdContent checks the private ad carries the pairing attributes.
func TestPrivateAdContent(t *testing.T) {
	slots := buildTestSlots(t, 1, Resources{Cpus: 4, MemoryMB: 8000, DiskKB: 100000})
	ad := slots[0].PrivateAd()
	if v, ok := ad.EvaluateAttrString("Name"); !ok || v != "slot1@testhost" {
		t.Errorf("private Name = %q (ok=%v), want slot1@testhost", v, ok)
	}
	if v, ok := ad.EvaluateAttrString("MyType"); !ok || v != "Machine" {
		t.Errorf("private MyType = %q (ok=%v), want Machine", v, ok)
	}
}
