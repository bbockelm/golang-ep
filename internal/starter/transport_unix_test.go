package starter

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/cedar/stream"
)

// encryptedPeers returns two cedar streams over a real TCP connection (so they
// carry passable fds), keyed with the same AES-GCM key and advanced past the
// AAD handshake in both directions so each is at a clean, exportable boundary --
// exactly the state the ACTIVATE syscall stream is in when the startd hands it
// off. peerA plays the startd's side (the one that gets passed); peerB plays the
// shadow's side (stays put).
func encryptedPeers(t *testing.T) (peerA, peerB *stream.Stream) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	type acc struct {
		c   net.Conn
		err error
	}
	accCh := make(chan acc, 1)
	go func() {
		c, err := ln.Accept()
		accCh <- acc{c, err}
	}()
	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	a := <-accCh
	if a.err != nil {
		t.Fatalf("accept: %v", a.err)
	}

	peerA = stream.NewStream(dialed)
	peerB = stream.NewStream(a.c)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 7)
	}
	if err := peerA.SetSymmetricKey(key); err != nil {
		t.Fatalf("SetSymmetricKey A: %v", err)
	}
	if err := peerB.SetSymmetricKey(key); err != nil {
		t.Fatalf("SetSymmetricKey B: %v", err)
	}

	ctx := context.Background()
	// One encrypted frame each way -> finishedSend/RecvAAD true on both, counters
	// advanced, clean boundary.
	if err := peerA.SendMessage(ctx, []byte("ping")); err != nil {
		t.Fatalf("A send: %v", err)
	}
	if got, err := peerB.ReceiveFrame(ctx); err != nil || string(got) != "ping" {
		t.Fatalf("B recv = %q, %v", got, err)
	}
	if err := peerB.SendMessage(ctx, []byte("pong")); err != nil {
		t.Fatalf("B send: %v", err)
	}
	if got, err := peerA.ReceiveFrame(ctx); err != nil || string(got) != "pong" {
		t.Fatalf("A recv = %q, %v", got, err)
	}
	return peerA, peerB
}

// TestUnixTransportSyscallHandoff is the process-mode analogue of the inproc
// handoff test: it drives the real Unix-socket transport (starter listens,
// startd dials), passes an encrypted syscall stream via ExportCryptoState +
// SCM_RIGHTS, rebuilds it on the starter side with NewStreamWithCryptoState, and
// proves the rebuilt stream continues the AES-GCM session byte-exactly with the
// far peer -- in both directions, across a >4KB multi-frame message.
func TestUnixTransportSyscallHandoff(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	peerA, peerB := encryptedPeers(t)

	// Short socket path (macOS sun_path limit).
	sock := filepath.Join(shortTempDir(t), "s.sock")

	// Starter side listens; the startd side dials.
	sideCh := make(chan StarterSide, 1)
	errCh := make(chan error, 1)
	go func() {
		side, err := ListenStarter(sock, 10*time.Second, 0, nil)
		if err != nil {
			errCh <- err
			return
		}
		sideCh <- side
	}()

	u := NewUnixStartd(sock)
	if err := u.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = u.Close() }()

	var side StarterSide
	select {
	case side = <-sideCh:
	case err := <-errCh:
		t.Fatalf("ListenStarter: %v", err)
	case <-ctx.Done():
		t.Fatal("ListenStarter never returned")
	}
	defer func() { _ = side.Close() }()

	// Hand peerA across (startd side). PassSyscallConn exports the crypto state;
	// FinishActivation sends SyscallConnFollows + the fd.
	if err := u.PassSyscallConn(peerA); err != nil {
		t.Fatalf("PassSyscallConn: %v", err)
	}
	finErr := make(chan error, 1)
	go func() { finErr <- u.FinishActivation(ctx) }()

	rebuilt, err := side.SyscallConn(ctx)
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	if err := <-finErr; err != nil {
		t.Fatalf("FinishActivation: %v", err)
	}

	// The rebuilt stream must continue the session with peerB byte-exactly.
	// peerB -> rebuilt (shadow speaking to the process starter).
	if err := peerB.SendMessage(ctx, []byte("after-handoff")); err != nil {
		t.Fatalf("peerB send: %v", err)
	}
	if got, err := rebuilt.ReceiveFrame(ctx); err != nil || string(got) != "after-handoff" {
		t.Fatalf("rebuilt recv = %q, %v; want after-handoff (crypto state did not resume)", got, err)
	}
	// rebuilt -> peerB (the starter's first syscall bytes).
	if err := rebuilt.SendMessage(ctx, []byte("get_job_info")); err != nil {
		t.Fatalf("rebuilt send: %v", err)
	}
	if got, err := peerB.ReceiveFrame(ctx); err != nil || string(got) != "get_job_info" {
		t.Fatalf("peerB recv = %q, %v; want get_job_info", got, err)
	}

	// A large multi-frame message (>4KB) must also decrypt with counters in
	// lockstep.
	big := make([]byte, 9000)
	for i := range big {
		big[i] = byte(i % 251)
	}
	if err := peerB.SendMessage(ctx, big); err != nil {
		t.Fatalf("peerB big send: %v", err)
	}
	got, err := rebuilt.ReceiveFrame(ctx)
	if err != nil {
		t.Fatalf("rebuilt big recv: %v", err)
	}
	if len(got) != len(big) {
		t.Fatalf("rebuilt big recv len = %d, want %d", len(got), len(big))
	}
	for i := range big {
		if got[i] != big[i] {
			t.Fatalf("rebuilt big recv mismatch at %d", i)
		}
	}
}

// TestUnixTransportControlRelay proves the process StarterSide bridges ordinary
// control messages (both directions) transparently around the intercepted
// syscall handoff, so Run's transport contract is unchanged.
func TestUnixTransportControlRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	sock := filepath.Join(shortTempDir(t), "c.sock")
	sideCh := make(chan StarterSide, 1)
	errCh := make(chan error, 1)
	go func() {
		side, err := ListenStarter(sock, 10*time.Second, 0, nil)
		if err != nil {
			errCh <- err
			return
		}
		sideCh <- side
	}()

	u := NewUnixStartd(sock)
	if err := u.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = u.Close() }()

	var side StarterSide
	select {
	case side = <-sideCh:
	case err := <-errCh:
		t.Fatalf("ListenStarter: %v", err)
	case <-ctx.Done():
		t.Fatal("ListenStarter never returned")
	}
	defer func() { _ = side.Close() }()

	// startd -> starter: Activate rides the relay to Run's Control().
	act := &ActivateMsg{SandboxDir: "/tmp/dir_x", JobAd: nil}
	if err := WriteMessage(ctx, u.Control(), MsgActivate, MarshalActivate(act)); err != nil {
		t.Fatalf("write Activate: %v", err)
	}
	typ, ad, err := ReadMessage(ctx, side.Control())
	if err != nil {
		t.Fatalf("read Activate on starter side: %v", err)
	}
	if typ != MsgActivate {
		t.Fatalf("starter got %s, want Activate", MsgName(typ))
	}
	if got, _ := ParseActivate(ad); got.SandboxDir != "/tmp/dir_x" {
		t.Fatalf("relayed SandboxDir = %q", got.SandboxDir)
	}

	// starter -> startd: Hello rides the relay back to the startd's Control().
	hello := MarshalHello(&HelloMsg{StarterPid: 999, ClaimID: "<x:1>#1#1#...", Phase: "activated"})
	if err := WriteMessage(ctx, side.Control(), MsgHello, hello); err != nil {
		t.Fatalf("write Hello: %v", err)
	}
	typ, ad, err = ReadMessage(ctx, u.Control())
	if err != nil {
		t.Fatalf("read Hello on startd side: %v", err)
	}
	if typ != MsgHello {
		t.Fatalf("startd got %s, want Hello", MsgName(typ))
	}
	if h := ParseHello(ad); h.StarterPid != 999 {
		t.Fatalf("relayed StarterPid = %d, want 999", h.StarterPid)
	}
}

// shortTempDir returns a short temp dir (macOS caps unix socket paths near 104
// bytes; t.TempDir() can already exceed that with the socket basename appended).
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "eps")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
