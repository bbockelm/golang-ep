package starter

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/golang-htcondor/filetransfer"
	"github.com/bbockelm/golang-htcondor/syscalls"
)

// testClaimID is a synthetic startd claim id in the C++ format
// (<sinful>#bday#seq#[session_info]key); ParseClaimIDStrict and the session
// derivation only care about its shape, not about a live startd.
const testClaimID = `<127.0.0.1:9618>#1752000000#17#[Encryption="YES";Integrity="YES";CryptoMethods="AES";]0123456789abcdef0123456789abcdef`

// filetransSessionInfo mirrors the info string the golang-ap shadow hands the
// starter for the filetrans session (shadow/transfer.go setupTransfer).
const filetransSessionInfo = `[Encryption="YES";Integrity="YES";CryptoMethods="AES";]`

// fakeTransferServer is the in-package stand-in for the golang-ap shadow's
// transfer Endpoint: a real cedar server on localhost with the filetrans
// session imported (ImportFileTransferSession, exactly like the shadow), whose
// FILETRANS_UPLOAD handler serves a SendPlan via filetransfer.ServeUpload and
// whose FILETRANS_DOWNLOAD handler receives into a sink via ServeDownload --
// the same funcs the shadow endpoint calls.
type fakeTransferServer struct {
	t      *testing.T
	sinful string
	key    string // expected TransferKey (route token)
	plan   filetransfer.SendPlan
	sink   *recordSink
}

// startFakeTransferServer stands the server up and returns it. claimKey lets a
// test corrupt the session material independently of the route key.
func startFakeTransferServer(t *testing.T, ctx context.Context, claimID, transferKey string, plan filetransfer.SendPlan) *fakeTransferServer {
	t.Helper()
	cache := security.NewSessionCache()
	if _, err := security.ImportFileTransferSession(cache, claimID, security.ClaimSessionOptions{
		PeerFQU: security.ExecuteSideMatchSessionFQU,
	}); err != nil {
		t.Fatalf("ImportFileTransferSession: %v", err)
	}
	f := &fakeTransferServer{
		t:    t,
		key:  transferKey,
		plan: plan,
		sink: newRecordSink(),
	}
	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		SessionCache:   cache,
	})
	srv.Handle(commands.FILETRANS_UPLOAD, func(cctx context.Context, c *cedarserver.Conn) error {
		if err := f.checkKey(cctx, c); err != nil {
			return err
		}
		return filetransfer.ServeUpload(cctx, c.Stream, f.plan, filetransfer.Options{Logf: t.Logf})
	}, "WRITE")
	srv.Handle(commands.FILETRANS_DOWNLOAD, func(cctx context.Context, c *cedarserver.Conn) error {
		if err := f.checkKey(cctx, c); err != nil {
			return err
		}
		_, err := filetransfer.ServeDownload(cctx, c.Stream, f.sink, filetransfer.Options{Logf: t.Logf, ReceiveAck: true})
		return err
	}, "WRITE")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = srv.Serve(ctx, ln) }()
	f.sinful = fmt.Sprintf("<%s>", ln.Addr().String())
	return f
}

// checkKey reads the leading put_secret(TransferKey) + EOM (the endpoint's
// readTransKey) and verifies the route token.
func (f *fakeTransferServer) checkKey(ctx context.Context, c *cedarserver.Conn) error {
	in := message.NewMessageFromStream(c.Stream)
	key, err := in.GetString(ctx)
	if err != nil {
		return fmt.Errorf("fake server: reading TransferKey: %w", err)
	}
	for {
		if _, err := in.GetBytes(ctx, 1); err != nil {
			break
		}
	}
	if key != f.key {
		return fmt.Errorf("fake server: TransferKey mismatch (got %q)", key)
	}
	return nil
}

// recordSink records received files/dirs in memory (mutex-guarded: written on
// the server goroutine, read by the test).
type recordSink struct {
	mu    sync.Mutex
	files map[string]*bytes.Buffer
	modes map[string]int64
	dirs  []string
}

func newRecordSink() *recordSink {
	return &recordSink{files: map[string]*bytes.Buffer{}, modes: map[string]int64{}}
}

func (s *recordSink) Mkdir(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirs = append(s.dirs, name)
	return nil
}

type recordWriter struct {
	s    *recordSink
	name string
}

func (w *recordWriter) Write(p []byte) (int, error) {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	return w.s.files[w.name].Write(p)
}
func (w *recordWriter) Close() error { return nil }

func (s *recordSink) File(name string, mode int64, _ int64) (io.WriteCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.files[name] = &bytes.Buffer{}
	s.modes[name] = mode
	return &recordWriter{s: s, name: name}, nil
}

func (s *recordSink) content(name string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.files[name]
	if !ok {
		return "", false
	}
	return b.String(), true
}

func (s *recordSink) names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.files))
	for n := range s.files {
		out = append(out, n)
	}
	return out
}

// planFromDir builds a SendPlan from literal (name, content, mode) triples,
// materialized in dir.
func planFromDir(t *testing.T, dir string, files map[string]struct {
	content string
	mode    os.FileMode
}) filetransfer.SendPlan {
	t.Helper()
	plan := filetransfer.SendPlan{FinalTransfer: true}
	for name, spec := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(spec.content), spec.mode); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		src := p
		plan.Files = append(plan.Files, filetransfer.FileSpec{
			WireName: name,
			Mode:     int64(spec.mode.Perm()),
			Size:     int64(len(spec.content)),
			Open:     func() (io.ReadCloser, error) { return os.Open(src) },
		})
	}
	return plan
}

// filetransTriplet builds the get_sec_session_info reply material for claimID
// (the starter-side view of what the golang-ap shadow hands out).
func filetransTriplet(claimID string) *syscalls.SecSessionInfo {
	cid := security.ParseClaimIDStrict(claimID)
	return &syscalls.SecSessionInfo{
		FiletransID:   "filetrans." + cid.SecSessionID(),
		FiletransInfo: filetransSessionInfo,
		FiletransKey:  cid.SecSessionKey(),
	}
}

// transferJobAd builds a minimal transfer-enabled job ad pointing at the fake
// server.
func transferJobAd(socket, key string) *classad.ClassAd {
	ad := classad.New()
	_ = ad.Set("ShouldTransferFiles", "YES")
	_ = ad.Set("TransferSocket", socket)
	_ = ad.Set("TransferKey", key)
	_ = ad.Set("Out", "job.out")
	_ = ad.Set("Err", "job.err")
	return ad
}

// newTransferState runs setupTransfer against the fake server's material,
// failing the test on error.
func newTransferState(t *testing.T, ad *classad.ClassAd, sandbox string, sec *syscalls.SecSessionInfo) *transferState {
	t.Helper()
	ts, err := setupTransfer(ad, sandbox, sec, t.Logf)
	if err != nil {
		t.Fatalf("setupTransfer: %v", err)
	}
	if ts == nil {
		t.Fatal("setupTransfer returned nil state for a transfer-enabled ad")
	}
	return ts
}

// TestShouldTransfer covers the ShouldTransferFiles decision table.
func TestShouldTransfer(t *testing.T) {
	cases := []struct {
		val  string
		set  bool
		want bool
	}{
		{"YES", true, true},
		{"IF_NEEDED", true, true},
		{"NO", true, false},
		{"no", true, false},
		{"", false, false}, // absent -> no transfer (documented)
	}
	for _, c := range cases {
		ad := classad.New()
		if c.set {
			_ = ad.Set("ShouldTransferFiles", c.val)
		}
		if got := shouldTransfer(ad); got != c.want {
			t.Errorf("shouldTransfer(%q set=%v) = %v, want %v", c.val, c.set, got, c.want)
		}
	}
}

// TestDownloadInputLoopback: the happy input path. The fake server (the same
// ServeUpload the golang-ap shadow endpoint calls) sends an executable, a data
// file, and a zero-byte file (exercising the PUT_FILE_EOM_NUM marker); they
// must land in the sandbox with the right bytes and modes, and the pre-exec
// snapshot must record them.
func TestDownloadInputLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	srcDir := t.TempDir()
	plan := planFromDir(t, srcDir, map[string]struct {
		content string
		mode    os.FileMode
	}{
		"job.sh":    {"#!/bin/sh\nexit 0\n", 0o755},
		"input.dat": {"hello-input", 0o644},
		"empty.dat": {"", 0o644},
	})
	const transferKey = "1#abc123"
	srv := startFakeTransferServer(t, ctx, testClaimID, transferKey, plan)

	sandbox := filepath.Join(t.TempDir(), "sandbox")
	ts := newTransferState(t, transferJobAd(srv.sinful, transferKey), sandbox, filetransTriplet(testClaimID))
	if err := ts.downloadInput(ctx); err != nil {
		t.Fatalf("downloadInput: %v", err)
	}

	for name, want := range map[string]string{
		"job.sh":    "#!/bin/sh\nexit 0\n",
		"input.dat": "hello-input",
		"empty.dat": "",
	} {
		data, err := os.ReadFile(filepath.Join(sandbox, name))
		if err != nil {
			t.Fatalf("reading %s from sandbox: %v", name, err)
		}
		if string(data) != want {
			t.Errorf("%s = %q, want %q", name, data, want)
		}
	}
	if info, err := os.Stat(filepath.Join(sandbox, "job.sh")); err != nil || info.Mode().Perm() != 0o755 {
		t.Errorf("job.sh mode = %v (err=%v), want 0755", info.Mode(), err)
	}
	for _, name := range []string{"job.sh", "input.dat", "empty.dat"} {
		if _, ok := ts.snapshot[name]; !ok {
			t.Errorf("pre-exec snapshot missing %s", name)
		}
	}
}

// TestUploadOutputLoopback: the default output selection. After a simulated
// run that leaves the input unchanged, creates result.txt, and writes stdio
// files, the upload must carry result.txt plus _condor_stdout/_condor_stderr
// -- and NOT the unchanged input or executable.
func TestUploadOutputLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	srcDir := t.TempDir()
	plan := planFromDir(t, srcDir, map[string]struct {
		content string
		mode    os.FileMode
	}{
		"job.sh":    {"#!/bin/sh\nexit 0\n", 0o755},
		"input.dat": {"hello-input", 0o644},
	})
	const transferKey = "2#def456"
	srv := startFakeTransferServer(t, ctx, testClaimID, transferKey, plan)

	sandbox := filepath.Join(t.TempDir(), "sandbox")
	ad := transferJobAd(srv.sinful, transferKey)
	ts := newTransferState(t, ad, sandbox, filetransTriplet(testClaimID))
	if err := ts.downloadInput(ctx); err != nil {
		t.Fatalf("downloadInput: %v", err)
	}

	// Simulate the job: one new output file plus captured stdio.
	for name, content := range map[string]string{
		"result.txt": "RESULT:hello-input\n",
		"job.out":    "job stdout ok\n",
		"job.err":    "",
	} {
		if err := os.WriteFile(filepath.Join(sandbox, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	if err := ts.uploadOutput(ctx, ad); err != nil {
		t.Fatalf("uploadOutput: %v", err)
	}

	if got, ok := srv.sink.content("result.txt"); !ok || got != "RESULT:hello-input\n" {
		t.Errorf("server got result.txt = %q (ok=%v)", got, ok)
	}
	if got, ok := srv.sink.content(stdoutRemapName); !ok || got != "job stdout ok\n" {
		t.Errorf("server got %s = %q (ok=%v)", stdoutRemapName, got, ok)
	}
	if got, ok := srv.sink.content(stderrRemapName); !ok || got != "" {
		t.Errorf("server got %s = %q (ok=%v), want empty", stderrRemapName, got, ok)
	}
	for _, unwanted := range []string{"input.dat", "job.sh", "job.out", "job.err"} {
		if _, ok := srv.sink.content(unwanted); ok {
			t.Errorf("server received %s, which should not be in the default output plan (%v)", unwanted, srv.sink.names())
		}
	}
}

// TestUploadOutputExplicitList: a present TransferOutput attribute selects
// exactly the named files (plus stdio under remap names) even when other new
// files exist.
func TestUploadOutputExplicitList(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const transferKey = "3#aaa111"
	srv := startFakeTransferServer(t, ctx, testClaimID, transferKey, filetransfer.SendPlan{FinalTransfer: true})

	sandbox := filepath.Join(t.TempDir(), "sandbox")
	if err := os.MkdirAll(sandbox, 0o700); err != nil {
		t.Fatal(err)
	}
	ad := transferJobAd(srv.sinful, transferKey)
	_ = ad.Set("TransferOutput", "wanted.txt")
	ts := newTransferState(t, ad, sandbox, filetransTriplet(testClaimID))
	if err := ts.downloadInput(ctx); err != nil {
		t.Fatalf("downloadInput (empty plan): %v", err)
	}
	for name, content := range map[string]string{
		"wanted.txt":   "picked\n",
		"unwanted.txt": "not picked\n",
		"job.out":      "stdout\n",
	} {
		if err := os.WriteFile(filepath.Join(sandbox, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	if err := ts.uploadOutput(ctx, ad); err != nil {
		t.Fatalf("uploadOutput: %v", err)
	}
	if got, ok := srv.sink.content("wanted.txt"); !ok || got != "picked\n" {
		t.Errorf("server got wanted.txt = %q (ok=%v)", got, ok)
	}
	if got, ok := srv.sink.content(stdoutRemapName); !ok || got != "stdout\n" {
		t.Errorf("server got %s = %q (ok=%v)", stdoutRemapName, got, ok)
	}
	if _, ok := srv.sink.content("unwanted.txt"); ok {
		t.Errorf("server received unwanted.txt despite explicit TransferOutput")
	}
}

// TestUploadOutputMissingFile: a TransferOutput entry that does not exist is a
// clean error (before any bytes move).
func TestUploadOutputMissingFile(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const transferKey = "4#bbb222"
	srv := startFakeTransferServer(t, ctx, testClaimID, transferKey, filetransfer.SendPlan{FinalTransfer: true})

	sandbox := filepath.Join(t.TempDir(), "sandbox")
	if err := os.MkdirAll(sandbox, 0o700); err != nil {
		t.Fatal(err)
	}
	ad := transferJobAd(srv.sinful, transferKey)
	_ = ad.Set("TransferOutput", "missing.txt")
	ts := newTransferState(t, ad, sandbox, filetransTriplet(testClaimID))

	err := ts.uploadOutput(ctx, ad)
	if err == nil {
		t.Fatal("uploadOutput succeeded despite a missing TransferOutput file")
	}
	if !strings.Contains(err.Error(), "missing.txt") {
		t.Errorf("error %q does not name the missing file", err)
	}
}

// TestDownloadInputWrongSessionKey: session material with the wrong key must
// not yield a usable transfer (the server cannot decrypt our TransferKey
// message, or rejects the stream); downloadInput must error out.
func TestDownloadInputWrongSessionKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const transferKey = "5#ccc333"
	srv := startFakeTransferServer(t, ctx, testClaimID, transferKey, filetransfer.SendPlan{FinalTransfer: true})

	sec := filetransTriplet(testClaimID)
	sec.FiletransKey = "ffffffffffffffffffffffffffffffff" // not the claim secret

	sandbox := filepath.Join(t.TempDir(), "sandbox")
	ts := newTransferState(t, transferJobAd(srv.sinful, transferKey), sandbox, sec)
	if err := ts.downloadInput(ctx); err == nil {
		t.Fatal("downloadInput succeeded with the wrong session key")
	}
}

// TestDownloadInputWrongTransferKey: a bad route token is rejected by the
// server after the (valid) session handshake; the client sees the stream die.
func TestDownloadInputWrongTransferKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	srv := startFakeTransferServer(t, ctx, testClaimID, "6#real-key", filetransfer.SendPlan{FinalTransfer: true})

	sandbox := filepath.Join(t.TempDir(), "sandbox")
	ts := newTransferState(t, transferJobAd(srv.sinful, "6#wrong-key"), sandbox, filetransTriplet(testClaimID))
	if err := ts.downloadInput(ctx); err == nil {
		t.Fatal("downloadInput succeeded with the wrong TransferKey")
	}
}

// TestSetupTransferNoSocket: an ad without TransferSocket/TransferKey yields a
// nil state (no transfer configured by the shadow) and no error.
func TestSetupTransferNoSocket(t *testing.T) {
	ad := classad.New()
	_ = ad.Set("ShouldTransferFiles", "YES")
	ts, err := setupTransfer(ad, t.TempDir(), filetransTriplet(testClaimID), t.Logf)
	if err != nil || ts != nil {
		t.Fatalf("setupTransfer = (%v, %v), want (nil, nil)", ts, err)
	}
}

// TestSetupTransferNoSession: transfer attributes without session material is
// an error (we refuse to dial without the filetrans session).
func TestSetupTransferNoSession(t *testing.T) {
	ad := transferJobAd("<127.0.0.1:1>", "key")
	if _, err := setupTransfer(ad, t.TempDir(), nil, t.Logf); err == nil {
		t.Fatal("setupTransfer accepted a transfer ad without session material")
	}
}
