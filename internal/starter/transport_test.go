package starter

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/stream"
)

// sendRecv pushes one control message across an inproc pair and returns what
// the other side decodes.
func sendRecv(t *testing.T, from, to *stream.Stream, msgType int, ad *classad.ClassAd) (int, *classad.ClassAd) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- WriteMessage(ctx, from, msgType, ad) }()
	gotType, gotAd, err := ReadMessage(ctx, to)
	if err != nil {
		t.Fatalf("ReadMessage(%s): %v", MsgName(msgType), err)
	}
	if werr := <-errCh; werr != nil {
		t.Fatalf("WriteMessage(%s): %v", MsgName(msgType), werr)
	}
	return gotType, gotAd
}

// TestControlCodecRoundTrip round-trips every control message type -- both
// directions of the codec -- over a real inproc (net.Pipe) transport pair,
// checking the typed marshal helpers decode to what was encoded.
func TestControlCodecRoundTrip(t *testing.T) {
	startdT, starterT := NewInprocPair()
	defer func() { _ = startdT.Close() }()
	defer func() { _ = starterT.Close() }()
	sd, st := startdT.Control(), starterT.Control()

	// Activate (startd -> starter) with embedded job/slot ads + env overlay.
	jobAd := classad.New()
	_ = jobAd.Set("Cmd", "/bin/sh")
	_ = jobAd.Set("Arguments", "-c 'echo hi; exit 0'")
	_ = jobAd.Set("JobUniverse", int64(5))
	_ = jobAd.Set("Requirements", true)
	slotAd := classad.New()
	_ = slotAd.Set("Name", "slot1@host")
	_ = slotAd.Set("Cpus", int64(2))
	want := &ActivateMsg{
		JobAd:      jobAd,
		SlotAd:     slotAd,
		SandboxDir: "/tmp/dir_123",
		EnvOverlay: map[string]string{"FOO": "bar baz", "X": "1"},
	}
	typ, ad := sendRecv(t, sd, st, MsgActivate, MarshalActivate(want))
	if typ != MsgActivate {
		t.Fatalf("type = %s, want Activate", MsgName(typ))
	}
	got, err := ParseActivate(ad)
	if err != nil {
		t.Fatalf("ParseActivate: %v", err)
	}
	if got.SandboxDir != want.SandboxDir {
		t.Errorf("SandboxDir = %q, want %q", got.SandboxDir, want.SandboxDir)
	}
	if !reflect.DeepEqual(got.EnvOverlay, want.EnvOverlay) {
		t.Errorf("EnvOverlay = %v, want %v", got.EnvOverlay, want.EnvOverlay)
	}
	if v, _ := got.JobAd.EvaluateAttrString("Cmd"); v != "/bin/sh" {
		t.Errorf("JobAd.Cmd = %q, want /bin/sh", v)
	}
	if v, _ := got.JobAd.EvaluateAttrString("Arguments"); v != "-c 'echo hi; exit 0'" {
		t.Errorf("JobAd.Arguments = %q did not round-trip", v)
	}
	if v, ok := got.JobAd.EvaluateAttrInt("JobUniverse"); !ok || v != 5 {
		t.Errorf("JobAd.JobUniverse = %d (ok=%v), want 5", v, ok)
	}
	if v, ok := got.SlotAd.EvaluateAttrInt("Cpus"); !ok || v != 2 {
		t.Errorf("SlotAd.Cpus = %d (ok=%v), want 2", v, ok)
	}

	// VacateSoft (startd -> starter).
	vs := &VacateSoftMsg{Reason: "test vacate", MaxVacateTime: 30}
	typ, ad = sendRecv(t, sd, st, MsgVacateSoft, MarshalVacateSoft(vs))
	if typ != MsgVacateSoft {
		t.Fatalf("type = %s, want VacateSoft", MsgName(typ))
	}
	if gotVS := ParseVacateSoft(ad); !reflect.DeepEqual(gotVS, vs) {
		t.Errorf("VacateSoft = %+v, want %+v", gotVS, vs)
	}

	// VacateHard / Reattach (bare ads).
	for _, mt := range []int{MsgVacateHard, MsgReattach} {
		typ, _ = sendRecv(t, sd, st, mt, nil)
		if typ != mt {
			t.Fatalf("type = %s, want %s", MsgName(typ), MsgName(mt))
		}
	}

	// Hello (starter -> startd).
	h := &HelloMsg{StarterPid: 4242, StarterAddr: "<127.0.0.1:9999>", ClaimID: "<1.2.3.4:1>#111#5#...", JobPid: 4243, Phase: "executing"}
	typ, ad = sendRecv(t, st, sd, MsgHello, MarshalHello(h))
	if typ != MsgHello {
		t.Fatalf("type = %s, want Hello", MsgName(typ))
	}
	if gotH := ParseHello(ad); !reflect.DeepEqual(gotH, h) {
		t.Errorf("Hello = %+v, want %+v", gotH, h)
	}

	// Update (starter -> startd).
	upd := classad.New()
	_ = upd.Set("JobState", "Running")
	_ = upd.Set("JobPid", int64(4243))
	typ, ad = sendRecv(t, st, sd, MsgUpdate, upd)
	if typ != MsgUpdate {
		t.Fatalf("type = %s, want Update", MsgName(typ))
	}
	if v, _ := ad.EvaluateAttrString("JobState"); v != "Running" {
		t.Errorf("Update JobState = %q", v)
	}

	// Final (starter -> startd): scalar status/reason ride in the ad.
	finalAd := classad.New()
	_ = finalAd.Set("ExitCode", int64(3))
	_ = finalAd.Set("ExitBySignal", false)
	typ, ad = sendRecv(t, st, sd, MsgFinal, MarshalFinal(finalAd, 3<<8, 100))
	if typ != MsgFinal {
		t.Fatalf("type = %s, want Final", MsgName(typ))
	}
	gotFinal, status, reason := ParseFinal(ad)
	if status != 3<<8 || reason != 100 {
		t.Errorf("Final status/reason = %d/%d, want %d/100", status, reason, 3<<8)
	}
	if v, ok := gotFinal.EvaluateAttrInt("ExitCode"); !ok || v != 3 {
		t.Errorf("Final ExitCode = %d (ok=%v), want 3", v, ok)
	}

	// Exited (starter -> startd).
	typ, _ = sendRecv(t, st, sd, MsgExited, nil)
	if typ != MsgExited {
		t.Fatalf("type = %s, want Exited", MsgName(typ))
	}
}

// TestInprocSyscallConnHandoff exercises the PassSyscallConn/SyscallConn
// channel: the pointer arrives intact, a second pass fails, and a closed
// transport unblocks a waiting receiver.
func TestInprocSyscallConnHandoff(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	startdT, starterT := NewInprocPair()
	defer func() { _ = startdT.Close() }()
	defer func() { _ = starterT.Close() }()

	pipeA, pipeB := newStreamPipe()
	defer func() { _ = pipeB.Close() }()
	if err := startdT.PassSyscallConn(pipeA); err != nil {
		t.Fatalf("PassSyscallConn: %v", err)
	}
	got, err := starterT.SyscallConn(ctx)
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	if got != pipeA {
		t.Fatal("SyscallConn returned a different stream pointer")
	}
	if err := startdT.PassSyscallConn(pipeA); err == nil {
		t.Fatal("second PassSyscallConn succeeded, want error")
	}

	// A waiter on a closed transport must unblock with an error.
	sd2, st2 := NewInprocPair()
	errCh := make(chan error, 1)
	go func() {
		_, err := st2.SyscallConn(ctx)
		errCh <- err
	}()
	_ = sd2.Close()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("SyscallConn on closed transport returned nil error")
		}
	case <-ctx.Done():
		t.Fatal("SyscallConn never unblocked after Close")
	}
	_ = st2.Close()
}
