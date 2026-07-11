// This file implements the starter's role as HTCondor's file-transfer *client*
// (Stage 4): before exec it pulls the input sandbox from the shadow's transfer
// server, and after the job exits it pushes the output sandbox back.
//
// Wire shape (C++ ground truth: src/condor_utils/file_transfer.cpp client side,
// src/condor_starter.V6.1/jic_shadow.cpp beginInputTransfer/transferOutput; Go
// oracle: golang-ap/shadow/transfer.go, the proven server peer):
//
//   - input:  startCommand(FILETRANS_UPLOAD=61000) over the filetrans security
//     session -> put_secret(TransferKey) + EOM -> filetransfer.ReceiveStream
//     (the server SENDS its input plan; we receive into the sandbox).
//   - output: startCommand(FILETRANS_DOWNLOAD=61001) -> put_secret(TransferKey)
//     + EOM -> filetransfer.SendStream with final_transfer=1 (we SEND the
//     output plan; the server lands it in the job's Iwd).
//
// TransferSocket and TransferKey come from the get_job_info job ad; the
// filetrans security session material ({id, info, key}) comes from the
// get_sec_session_info reply. On the encrypted filetrans session a put_secret
// is byte-identical to an ordinary string put (see startd/alive.go), so the
// key travels as a plain PutString and the server reads it with GetString.
package starter

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/cedar/stream"
	"github.com/bbockelm/golang-htcondor/filetransfer"
	"github.com/bbockelm/golang-htcondor/syscalls"
)

// stdout/stderr sandbox-to-wire names (file_transfer.cpp StdoutRemapName /
// StderrRemapName). The starter sends the job's captured Out/Err under these
// names; the shadow's output sink remaps them back to the job's requested
// Out/Err in the Iwd (see golang-ap shadow buildOutputSink).
const (
	stdoutRemapName = "_condor_stdout"
	stderrRemapName = "_condor_stderr"
)

// shouldTransfer reports whether the job wants sandbox file transfer.
// ShouldTransferFiles YES and IF_NEEDED both transfer at this stage (the
// IF_NEEDED same-filesystem-domain optimization is not implemented); an
// explicit "NO" -- or an absent attribute -- does not. Treating "absent" as NO
// is our documented choice: every ad the Stage-3 flow ran carried an explicit
// "NO", and a shadow that wants transfer must inject TransferSocket/TransferKey
// anyway, which only happens alongside an explicit YES/IF_NEEDED.
func shouldTransfer(jobAd *classad.ClassAd) bool {
	v, ok := jobAd.EvaluateAttrString("ShouldTransferFiles")
	if !ok || v == "" {
		return false
	}
	return !strings.EqualFold(v, "NO")
}

// fileStamp is one file's identity in the pre-exec sandbox snapshot.
type fileStamp struct {
	size  int64
	mtime time.Time
}

// transferState is the starter's per-activation file-transfer client state.
type transferState struct {
	cache     *security.SessionCache // holds the imported filetrans session
	sessionID string                 // "filetrans.<claim session id>"
	socket    string                 // TransferSocket: the shadow endpoint's sinful
	key       string                 // TransferKey: the route token, sent as put_secret
	sandbox   string

	// snapshot is the top-level sandbox content right after input transfer
	// (before exec); uploadOutput's default plan sends what is new or changed
	// relative to it.
	snapshot map[string]fileStamp

	logf func(format string, args ...any)
}

// setupTransfer builds the starter's transfer client from the get_job_info ad
// (TransferSocket + TransferKey) and the get_sec_session_info reply (the
// filetrans {id, info, key} triplet). It registers the filetrans session in a
// starter-local session cache via cedar's CreateNonNegotiatedSession -- the API
// that takes an explicit {id, info, key} triplet (the same HKDF key derivation
// and AES-GCM policy ImportFileTransferSession applies on the shadow side, so
// both ends hold the same key under the same "filetrans.<sid>" id).
//
// Returns (nil, nil) when the job ad carries no TransferSocket/TransferKey: the
// shadow did not configure transfer, so the job runs without it (the C++
// starter behaves the same when the ad has no transfer attributes).
func setupTransfer(jobAd *classad.ClassAd, sandbox string, sec *syscalls.SecSessionInfo, logf func(string, ...any)) (*transferState, error) {
	socket, _ := jobAd.EvaluateAttrString("TransferSocket")
	key, _ := jobAd.EvaluateAttrString("TransferKey")
	if socket == "" || key == "" {
		return nil, nil
	}
	if sec == nil || sec.FiletransID == "" || sec.FiletransKey == "" {
		return nil, fmt.Errorf("starter: job ad requests file transfer but the shadow provided no filetrans session (get_sec_session_info)")
	}

	cache := security.NewSessionCache()
	entry, err := security.CreateNonNegotiatedSession(&security.InheritedSession{
		Type:        security.SessionTypeNormal,
		SessionID:   sec.FiletransID,
		SessionInfo: sec.FiletransInfo,
		SessionKey:  sec.FiletransKey,
	}, socket)
	if err != nil {
		return nil, fmt.Errorf("starter: importing filetrans session: %w", err)
	}
	entry.SetInherited(true) // runtime session material; never persist
	cache.Store(entry)

	return &transferState{
		cache:     cache,
		sessionID: sec.FiletransID,
		socket:    socket,
		key:       key,
		sandbox:   sandbox,
		logf:      logf,
	}, nil
}

// dial connects to the shadow's transfer endpoint with startCommand(cmd) over
// the filetrans session (resumed by explicit SessionID, the pattern of
// startd.Client.connect / startd/alive.go), verifies the stream is encrypted
// (put_secret must never travel in the clear), and sends the TransferKey + EOM.
// The returned client owns the connection; Close it when the stream is done.
func (ts *transferState) dial(ctx context.Context, cmd int) (*client.HTCondorClient, *stream.Stream, error) {
	sec := &security.SecurityConfig{
		Command:      cmd,
		PeerName:     ts.socket,
		SessionCache: ts.cache,
		SessionID:    ts.sessionID,
	}
	hc, err := client.ConnectAndAuthenticate(ctx, ts.socket, sec)
	if err != nil {
		return nil, nil, fmt.Errorf("starter: connect/resume filetrans session for command %d: %w", cmd, err)
	}
	if neg := hc.GetSecurityNegotiation(); neg == nil || !neg.Encryption {
		_ = hc.Close()
		return nil, nil, fmt.Errorf("starter: filetrans connection is not encrypted; refusing to send TransferKey")
	}
	st := hc.GetStream()

	// put_secret(TransferKey) + end_of_message: on the encrypted session this is
	// an ordinary string put (the server's readTransKey reads it with GetString).
	out := message.NewMessageForStream(st)
	if err := out.PutString(ctx, ts.key); err != nil {
		_ = hc.Close()
		return nil, nil, fmt.Errorf("starter: sending TransferKey: %w", err)
	}
	if err := out.FinishMessage(ctx); err != nil {
		_ = hc.Close()
		return nil, nil, fmt.Errorf("starter: flushing TransferKey: %w", err)
	}
	return hc, st, nil
}

// downloadInput pulls the input sandbox: FILETRANS_UPLOAD asks the server to
// upload its input plan to us, received into the sandbox. ReceiveAck is set:
// the sender (SendStream / C++ DoUpload) always finishes with a TransferAck
// exchange. On success it records the pre-exec sandbox snapshot that
// uploadOutput's default output selection diffs against.
func (ts *transferState) downloadInput(ctx context.Context) error {
	hc, st, err := ts.dial(ctx, commands.FILETRANS_UPLOAD)
	if err != nil {
		return err
	}
	defer func() { _ = hc.Close() }()

	sink := &sandboxSink{dir: ts.sandbox, logf: ts.logf}
	res, err := filetransfer.ReceiveStream(ctx, st, sink, filetransfer.Options{
		Logf:       ts.logf,
		ReceiveAck: true,
	})
	if err != nil {
		return fmt.Errorf("starter: input transfer: %w", err)
	}
	ts.logf("starter: input transfer complete: files=%v dirs=%v", res.Files, res.Dirs)
	ts.snapshot = snapshotSandbox(ts.sandbox)
	return nil
}

// uploadOutput pushes the output sandbox: FILETRANS_DOWNLOAD asks the server to
// download from us, so we SEND the output plan with final_transfer=1 (the files
// land in the job's real Iwd, not a spool).
//
// Output-file selection (documented semantics for the golang-ap shadow oracle):
//
//   - The job's captured stdout/stderr (relative Out/Err, not /dev/null) are
//     sent under the wire names _condor_stdout/_condor_stderr; the shadow's
//     sink remaps them to the job's requested names in the Iwd. Missing or
//     absolute Out/Err are skipped.
//   - When the ad names TransferOutput (or the legacy TransferOutputFiles),
//     exactly those sandbox-relative files are sent; a named file that does
//     not exist is an error (the C++ starter holds the job for this too).
//   - Otherwise (the C++ "all new or modified top-level files" default, as in
//     FileTransfer::Init's IF_NEEDED/whole-sandbox behavior): every top-level
//     regular file in the sandbox that is new or changed (size or mtime)
//     relative to the post-input-transfer snapshot is sent. Subdirectories are
//     not walked in this default mode -- a documented Stage-4 simplification
//     (explicit TransferOutput entries and the shadow's CmdMkdir path still
//     cover nested outputs when named).
func (ts *transferState) uploadOutput(ctx context.Context, jobAd *classad.ClassAd) error {
	plan, err := ts.buildOutputPlan(jobAd)
	if err != nil {
		return err
	}

	hc, st, err := ts.dial(ctx, commands.FILETRANS_DOWNLOAD)
	if err != nil {
		return err
	}
	defer func() { _ = hc.Close() }()

	if err := filetransfer.SendStream(ctx, st, plan, filetransfer.Options{Logf: ts.logf}); err != nil {
		return fmt.Errorf("starter: output transfer: %w", err)
	}
	ts.logf("starter: output transfer complete: %d files", len(plan.Files))
	return nil
}

// buildOutputPlan assembles the final-transfer send plan per the selection
// rules documented on uploadOutput.
func (ts *transferState) buildOutputPlan(jobAd *classad.ClassAd) (filetransfer.SendPlan, error) {
	plan := filetransfer.SendPlan{FinalTransfer: true}
	seen := map[string]bool{}

	add := func(wireName, relSource string, required bool) error {
		if wireName == "" || seen[wireName] {
			return nil
		}
		source := filepath.Join(ts.sandbox, relSource)
		info, err := os.Stat(source)
		if err != nil {
			if required {
				return fmt.Errorf("starter: output file %q: %w", relSource, err)
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			if required {
				return fmt.Errorf("starter: output file %q is not a regular file", relSource)
			}
			return nil
		}
		src := source
		plan.Files = append(plan.Files, filetransfer.FileSpec{
			WireName: wireName,
			Mode:     int64(info.Mode().Perm()),
			Size:     info.Size(),
			Open:     func() (io.ReadCloser, error) { return os.Open(src) },
		})
		seen[wireName] = true
		return nil
	}

	// Captured stdout/stderr under their remap wire names. Only sandbox-relative
	// paths qualify (absolute Out/Err were written in place, not in the sandbox).
	stdioRel := map[string]string{} // sandbox-relative name -> remap wire name
	for attr, wire := range map[string]string{"Out": stdoutRemapName, "Err": stderrRemapName} {
		if p, _ := jobAd.EvaluateAttrString(attr); p != "" && p != nullFile && !filepath.IsAbs(p) {
			if err := add(wire, p, false); err != nil {
				return plan, err
			}
			stdioRel[filepath.Clean(p)] = wire
		}
	}

	// Explicit TransferOutput list (TransferOutputFiles is the legacy spelling).
	// A PRESENT attribute -- even one listing nothing -- selects the explicit
	// mode, matching the C++ starter (an empty list means "only stdout/stderr").
	list, explicit := jobAd.EvaluateAttrString("TransferOutput")
	if !explicit {
		list, explicit = jobAd.EvaluateAttrString("TransferOutputFiles")
	}
	if explicit {
		for _, f := range splitFileList(list) {
			if err := add(f, f, true); err != nil {
				return plan, err
			}
		}
		return plan, nil
	}

	// Default: new-or-changed top-level regular files since the pre-exec
	// snapshot, excluding the stdio files already sent under remap names.
	now := snapshotSandbox(ts.sandbox)
	names := make([]string, 0, len(now))
	for name := range now {
		names = append(names, name)
	}
	// Deterministic wire order (map iteration is randomized).
	sort.Strings(names)
	for _, name := range names {
		if _, isStdio := stdioRel[name]; isStdio {
			continue
		}
		if name == stdoutRemapName || name == stderrRemapName {
			continue
		}
		st := now[name]
		if old, ok := ts.snapshot[name]; ok && old.size == st.size && old.mtime.Equal(st.mtime) {
			continue // unchanged since before exec
		}
		if err := add(name, name, false); err != nil {
			return plan, err
		}
	}
	return plan, nil
}

// snapshotSandbox records the top-level regular files of dir. A missing or
// unreadable dir yields an empty snapshot.
func snapshotSandbox(dir string) map[string]fileStamp {
	out := map[string]fileStamp{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out[e.Name()] = fileStamp{size: info.Size(), mtime: info.ModTime()}
	}
	return out
}

// sandboxSink lands received input files in the starter's sandbox (the client
// mirror of the golang-ap shadow's iwdSink, including its path-traversal
// guard). golang-htcondor's filetransfer package defines only the Sink
// interface -- its existing implementations (the shadow's iwdSink, the tool's
// tarSink) are unexported in their packages, so the starter carries its own.
type sandboxSink struct {
	dir  string
	logf func(format string, args ...any)
}

func (s *sandboxSink) dest(name string) (string, error) {
	clean := filepath.Clean(name)
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("starter: refusing input path outside sandbox: %q", name)
	}
	return filepath.Join(s.dir, clean), nil
}

func (s *sandboxSink) Mkdir(name string) error {
	dst, err := s.dest(name)
	if err != nil {
		return err
	}
	return os.MkdirAll(dst, 0o755)
}

func (s *sandboxSink) File(name string, mode int64, _ int64) (io.WriteCloser, error) {
	dst, err := s.dest(name)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return nil, err
	}
	perm := os.FileMode(mode).Perm()
	if perm == 0 {
		perm = 0o644
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return nil, err
	}
	if s.logf != nil {
		s.logf("starter: writing input file %s (mode %o)", dst, perm)
	}
	return f, nil
}

// splitFileList splits a comma/whitespace separated file list (TransferOutput),
// mirroring the shadow's tokenizer.
func splitFileList(list string) []string {
	fields := strings.FieldsFunc(list, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}
