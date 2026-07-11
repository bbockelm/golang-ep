package persist

import (
	"path/filepath"
	"testing"
)

// TestReopenRoundTrip is the Stage-7 read-path smoke test: write claim records
// across the lifecycle, close the store, reopen the SAME directory, and assert
// every record round-trips field-for-field. This proves the durable write side
// (Stage 6) and the enumerate-on-restart read side (Stage 7) agree.
func TestReopenRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claims")

	unclaimed := Record{
		SlotName:      "slot1@ep.example",
		ClaimID:       "<10.0.0.1:9618>#1700000000#1#secretkeymaterial1",
		PublicClaimID: "<10.0.0.1:9618>#1700000000#1#...",
		State:         "Unclaimed",
		Activity:      "Idle",
		Entered:       1700000000,
	}
	claimed := Record{
		SlotName:      "slot2@ep.example",
		ClaimID:       "<10.0.0.1:9618>#1700000000#2#secretkeymaterial2",
		PublicClaimID: "<10.0.0.1:9618>#1700000000#2#...",
		State:         "Claimed",
		Activity:      "Idle",
		ScheddAddr:    "<10.0.0.2:9618?sock=schedd>",
		ScheddName:    "schedd@ap.example",
		User:          "alice@example",
		ClientMachine: "ap.example",
		AliveInterval: 300,
		LeaseDeadline: 1700001800,
		Entered:       1700000100,
	}
	busy := Record{
		SlotName:      "slot3@ep.example",
		ClaimID:       "<10.0.0.1:9618>#1700000000#3#secretkeymaterial3",
		PublicClaimID: "<10.0.0.1:9618>#1700000000#3#...",
		State:         "Claimed",
		Activity:      "Busy",
		ScheddAddr:    "<10.0.0.2:9618?sock=schedd>",
		ScheddName:    "schedd@ap.example",
		User:          "bob@example",
		ClientMachine: "ap.example",
		AliveInterval: 300,
		LeaseDeadline: 1700001900,
		Entered:       1700000200,
		JobAd:         `[ Cmd = "/bin/sleep"; Arguments = "60"; JobUniverse = 5 ]`,
		StarterPid:    43110,
		StarterSocket: "/spool/ep/starters/abc123.sock",
		Sandbox:       "/execute/dir_43110",
	}

	records := []Record{unclaimed, claimed, busy}

	st, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for _, r := range records {
		if err := st.Put(r); err != nil {
			t.Fatalf("Put(%s): %v", r.SlotName, err)
		}
	}
	// Simulate a mid-lifecycle overwrite: slot1 gets claimed after its initial
	// Unclaimed mint. The upsert must win on reopen.
	claimedSlot1 := unclaimed
	claimedSlot1.State = "Claimed"
	claimedSlot1.Activity = "Idle"
	claimedSlot1.ScheddAddr = "<10.0.0.9:9618?sock=schedd>"
	claimedSlot1.AliveInterval = 120
	claimedSlot1.LeaseDeadline = 1700009999
	if err := st.Put(claimedSlot1); err != nil {
		t.Fatalf("Put(overwrite slot1): %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen the same directory: the Stage-7 recovery entry point.
	st2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen Open: %v", err)
	}
	defer func() { _ = st2.Close() }()

	list := st2.List()
	if len(list) != 3 {
		t.Fatalf("List after reopen: got %d records, want 3", len(list))
	}

	want := map[string]Record{
		"slot1@ep.example": claimedSlot1,
		"slot2@ep.example": claimed,
		"slot3@ep.example": busy,
	}
	for name, expect := range want {
		got, ok := st2.Get(name)
		if !ok {
			t.Fatalf("Get(%s) after reopen: not found", name)
		}
		if got != expect {
			t.Errorf("Get(%s) mismatch after reopen:\n got  %+v\n want %+v", name, got, expect)
		}
	}

	// A fresh write after reopen must also commit (proves the reopened store is
	// writable, not read-only).
	slot4 := Record{
		SlotName: "slot4@ep.example",
		ClaimID:  "<10.0.0.1:9618>#1700000000#4#secretkeymaterial4",
		State:    "Claimed",
		Activity: "Idle",
	}
	if err := st2.Put(slot4); err != nil {
		t.Fatalf("Put after reopen: %v", err)
	}
	if got, ok := st2.Get("slot4@ep.example"); !ok || got != slot4 {
		t.Fatalf("Get(slot4) after post-reopen Put: ok=%v got=%+v", ok, got)
	}

	// Delete removes a record durably within the session.
	st2.Delete("slot4@ep.example")
	if _, ok := st2.Get("slot4@ep.example"); ok {
		t.Errorf("Get(slot4) after Delete: still present")
	}
}
