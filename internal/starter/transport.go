// Package starter implements the EP's starter: the component that receives an
// activated job from the startd, drives the shadow's remote-syscall protocol
// (via golang-htcondor/syscalls), executes the job in a sandbox, and reports
// its lifecycle back to the startd over the StarterTransport control channel.
//
// The startd<->starter contract is ours to define (no C++ compatibility
// needed): one Transport interface, two implementations (Stage 3: goroutine
// mode over net.Pipe; Stage 6 adds a Unix-socket + SCM_RIGHTS process mode),
// and one wire codec -- every control message is [int msgType, ClassAd, EOM]
// in cedar message framing, both directions.
package starter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/stream"
)

// Transport is the STARTD's side of the startd<->starter channel: a framed
// control channel plus the one-shot handoff of the ACTIVATE_CLAIM connection
// (which becomes the starter's remote-syscall socket to the shadow).
type Transport interface {
	// Connect establishes the startd->starter control channel. Goroutine mode is
	// a no-op (the net.Pipe is already live); process mode dials the starter's
	// per-claim Unix socket with bounded retry (the starter binds+listens, the
	// startd dials -- redial-friendly for Stage 7). The supervisor calls it once,
	// before writing Activate; Control() is only valid after it returns nil.
	Connect(ctx context.Context) error
	// Control returns the framed control channel (cedar message codec). The
	// startd writes Activate/Vacate*/Reattach and reads Hello/Update/Final/
	// Exited on it. Valid only after Connect returns nil.
	Control() *stream.Stream
	// PassSyscallConn hands the live ACTIVATE_CLAIM connection's stream to the
	// starter. Called exactly once per activation, AFTER the OK reply has been
	// flushed on it (so the stream is at a clean message boundary and the
	// starter's first syscall bytes never interleave with the reply). Goroutine
	// mode passes the *stream.Stream pointer straight through -- buffered data and
	// AES state intact. Process mode captures the stream's exported crypto state
	// (ExportCryptoState) plus the underlying TCP fd here; the actual SCM_RIGHTS
	// send happens in FinishActivation so it stays serialized with Activate on the
	// single control writer. PassSyscallConn must not block.
	PassSyscallConn(*stream.Stream) error
	// FinishActivation completes the handoff after Activate: it waits for
	// PassSyscallConn to supply the ACTIVATE connection, then (process mode)
	// frames a SyscallConnFollows control message carrying the exported crypto
	// state and SCM_RIGHTS-passes the underlying TCP fd on the same Unix socket.
	// Goroutine mode is a no-op (PassSyscallConn already delivered the pointer).
	// The supervisor calls it immediately after Activate so all control-channel
	// writes stay on one goroutine. Honors ctx cancellation.
	FinishActivation(ctx context.Context) error
	Close() error
}

// StarterSide is the STARTER's end of the same channel: the mirror-image of
// Transport (the interface the startd holds). The starter reads Activate and
// receives the syscall stream the startd passed.
type StarterSide interface {
	// Control returns the starter's end of the framed control channel.
	Control() *stream.Stream
	// SyscallConn blocks until the startd hands over the ACTIVATE_CLAIM
	// connection (or ctx is done / the transport is closed).
	SyscallConn(ctx context.Context) (*stream.Stream, error)
	Close() error
}

// Control message types. startd -> starter use small positive integers;
// starter -> startd start at 101 so a decoding mix-up is unmistakable in logs.
const (
	// MsgActivate carries the activation: job ad, slot ad, sandbox dir, env
	// overlay (startd -> starter). The syscall conn follows via
	// PassSyscallConn.
	MsgActivate = 1
	// MsgVacateSoft asks for a graceful shutdown (SIGTERM -> SIGKILL
	// escalation). Declared for the codec; the Stage-3 starter logs it as
	// not-implemented (Stage 8: vacate).
	MsgVacateSoft = 2
	// MsgVacateHard demands an immediate kill (SIGKILL on -pgid).
	MsgVacateHard = 3
	// MsgReattach re-establishes a control channel after a startd restart
	// (Stage 7). Declared for the codec; Stage 3 logs it as not-implemented.
	MsgReattach = 4
	// MsgSuspend asks the starter to SIGSTOP the job's process group
	// (SUSPEND_CLAIM). Wired but not yet driven by a startd command (Stage 8
	// scopes the startd command surface to DEACTIVATE + vacate).
	MsgSuspend = 6
	// MsgContinue asks the starter to SIGCONT the job's process group
	// (CONTINUE_CLAIM). Wired but not yet driven by a startd command.
	MsgContinue = 7
	// MsgSyscallConnFollows is a PROCESS-MODE, TRANSPORT-INTERNAL message
	// (startd -> starter): it announces that the ACTIVATE_CLAIM syscall
	// connection is about to be SCM_RIGHTS-passed on the same Unix socket, and
	// carries the exported cedar crypto state (stream.ExportCryptoState) the
	// starter needs to rebuild the encrypted stream around the received fd. The
	// process StarterSide intercepts it and never forwards it to Run; goroutine
	// mode never sends it.
	MsgSyscallConnFollows = 5

	// MsgHello announces the starter on (re)connect: pid, address, claim id,
	// job pid, phase (starter -> startd).
	MsgHello = 101
	// MsgUpdate is the periodic job-status ad (doubles as the liveness
	// heartbeat).
	MsgUpdate = 102
	// MsgFinal carries the final job ad plus the raw waitpid status and JOB_*
	// reason code (as attributes; see MarshalFinal).
	MsgFinal = 103
	// MsgExited is the starter's last word: sent after Final, just before the
	// starter goroutine/process winds down.
	MsgExited = 104
)

// MsgName returns a human-readable name for a control message type (logs).
func MsgName(t int) string {
	switch t {
	case MsgActivate:
		return "Activate"
	case MsgVacateSoft:
		return "VacateSoft"
	case MsgVacateHard:
		return "VacateHard"
	case MsgReattach:
		return "Reattach"
	case MsgSuspend:
		return "Suspend"
	case MsgContinue:
		return "Continue"
	case MsgSyscallConnFollows:
		return "SyscallConnFollows"
	case MsgHello:
		return "Hello"
	case MsgUpdate:
		return "Update"
	case MsgFinal:
		return "Final"
	case MsgExited:
		return "Exited"
	}
	return fmt.Sprintf("unknown(%d)", t)
}

// WriteMessage sends one control message: [int msgType, ClassAd, EOM]. A nil
// ad is sent as an empty ClassAd so the codec is uniform.
func WriteMessage(ctx context.Context, st *stream.Stream, msgType int, ad *classad.ClassAd) error {
	if ad == nil {
		ad = classad.New()
	}
	out := message.NewMessageForStream(st)
	if err := out.PutInt(ctx, msgType); err != nil {
		return fmt.Errorf("starter: writing control msg type %s: %w", MsgName(msgType), err)
	}
	if err := out.PutClassAd(ctx, ad); err != nil {
		return fmt.Errorf("starter: writing control msg %s ad: %w", MsgName(msgType), err)
	}
	return out.FinishMessage(ctx)
}

// ReadMessage reads one control message: [int msgType, ClassAd, EOM]. The
// remainder of the message (should be empty) is drained so the stream stays
// framed for the next message.
func ReadMessage(ctx context.Context, st *stream.Stream) (int, *classad.ClassAd, error) {
	in := message.NewMessageFromStream(st)
	msgType, err := in.GetInt(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("starter: reading control msg type: %w", err)
	}
	ad, err := in.GetClassAd(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("starter: reading control msg %s ad: %w", MsgName(msgType), err)
	}
	if err := drainMessage(ctx, in); err != nil {
		return 0, nil, err
	}
	return msgType, ad, nil
}

// drainMessage consumes the remainder of a control message through its EOM
// marker (mirrors the shadow/syscalls drain helpers).
func drainMessage(ctx context.Context, in *message.Message) error {
	for {
		if _, err := in.GetBytes(ctx, 1); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("starter: draining control msg: %w", err)
		}
	}
}

// --- Activate ---

// ActivateMsg is the startd -> starter activation payload.
type ActivateMsg struct {
	// JobAd is the job ad from ACTIVATE_CLAIM. ADVISORY: the starter's
	// authoritative job ad comes from get_job_info on the syscall channel.
	JobAd *classad.ClassAd
	// SlotAd is the slot's machine ad at activation time.
	SlotAd *classad.ClassAd
	// SandboxDir is the job's scratch/sandbox directory (created by the
	// startd under EXECUTE; the starter MkdirAlls it defensively).
	SandboxDir string
	// EnvOverlay holds extra environment variables the startd injects into the
	// job environment (wins over the job ad's Environment).
	EnvOverlay map[string]string
}

// MarshalActivate encodes an ActivateMsg as the codec's ClassAd. The embedded
// job/slot ads travel as unparsed new-ClassAd strings (round-tripped through
// classad.Parse) so the codec stays [int, ClassAd, EOM] with no nesting.
func MarshalActivate(a *ActivateMsg) *classad.ClassAd {
	ad := classad.New()
	_ = ad.Set("SandboxDir", a.SandboxDir)
	if a.JobAd != nil {
		_ = ad.Set("JobAd", a.JobAd.StringWithPrivate())
	}
	if a.SlotAd != nil {
		_ = ad.Set("SlotAd", a.SlotAd.String())
	}
	if len(a.EnvOverlay) > 0 {
		var sb strings.Builder
		for k, v := range a.EnvOverlay {
			if sb.Len() > 0 {
				sb.WriteByte('\n')
			}
			sb.WriteString(k)
			sb.WriteByte('=')
			sb.WriteString(v)
		}
		_ = ad.Set("EnvOverlay", sb.String())
	}
	return ad
}

// ParseActivate decodes MarshalActivate's ad.
func ParseActivate(ad *classad.ClassAd) (*ActivateMsg, error) {
	out := &ActivateMsg{}
	out.SandboxDir, _ = ad.EvaluateAttrString("SandboxDir")
	if s, ok := ad.EvaluateAttrString("JobAd"); ok && s != "" {
		parsed, err := classad.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("starter: parsing Activate job ad: %w", err)
		}
		out.JobAd = parsed
	}
	if s, ok := ad.EvaluateAttrString("SlotAd"); ok && s != "" {
		parsed, err := classad.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("starter: parsing Activate slot ad: %w", err)
		}
		out.SlotAd = parsed
	}
	if s, ok := ad.EvaluateAttrString("EnvOverlay"); ok && s != "" {
		out.EnvOverlay = make(map[string]string)
		for _, line := range strings.Split(s, "\n") {
			if k, v, found := strings.Cut(line, "="); found && k != "" {
				out.EnvOverlay[k] = v
			}
		}
	}
	return out, nil
}

// --- VacateSoft ---

// VacateSoftMsg carries a graceful-vacate request.
type VacateSoftMsg struct {
	Reason        string
	MaxVacateTime int // seconds the starter may take before hard-killing
}

// MarshalVacateSoft encodes a VacateSoftMsg.
func MarshalVacateSoft(v *VacateSoftMsg) *classad.ClassAd {
	ad := classad.New()
	_ = ad.Set("Reason", v.Reason)
	_ = ad.Set("MaxVacateTime", int64(v.MaxVacateTime))
	return ad
}

// ParseVacateSoft decodes MarshalVacateSoft's ad.
func ParseVacateSoft(ad *classad.ClassAd) *VacateSoftMsg {
	out := &VacateSoftMsg{}
	out.Reason, _ = ad.EvaluateAttrString("Reason")
	if v, ok := ad.EvaluateAttrInt("MaxVacateTime"); ok {
		out.MaxVacateTime = int(v)
	}
	return out
}

// --- Hello ---

// HelloMsg announces the starter to the startd on (re)connect.
type HelloMsg struct {
	StarterPid  int
	StarterAddr string // starter's own command sinful; empty in Stage 3
	ClaimID     string // public claim id (never the secret)
	JobPid      int    // 0 until the job is running
	Phase       string // "activated", "executing", ...
}

// MarshalHello encodes a HelloMsg. The claim id travels as "PublicClaimId":
// it IS the public form, and the codec's PutClassAd redacts the private-V1
// attribute names ("ClaimId"/"Capability"), which would silently drop it.
func MarshalHello(h *HelloMsg) *classad.ClassAd {
	ad := classad.New()
	_ = ad.Set("StarterPid", int64(h.StarterPid))
	_ = ad.Set("StarterAddr", h.StarterAddr)
	_ = ad.Set("PublicClaimId", h.ClaimID)
	_ = ad.Set("JobPid", int64(h.JobPid))
	_ = ad.Set("Phase", h.Phase)
	return ad
}

// ParseHello decodes MarshalHello's ad.
func ParseHello(ad *classad.ClassAd) *HelloMsg {
	out := &HelloMsg{}
	if v, ok := ad.EvaluateAttrInt("StarterPid"); ok {
		out.StarterPid = int(v)
	}
	out.StarterAddr, _ = ad.EvaluateAttrString("StarterAddr")
	out.ClaimID, _ = ad.EvaluateAttrString("PublicClaimId")
	if v, ok := ad.EvaluateAttrInt("JobPid"); ok {
		out.JobPid = int(v)
	}
	out.Phase, _ = ad.EvaluateAttrString("Phase")
	return out
}

// --- Final ---

// finalStatusAttr / finalReasonAttr carry MsgFinal's scalar arguments inside
// the codec's single ClassAd (leading underscore: control-plane attrs, never
// job attrs).
const (
	finalStatusAttr = "_WaitpidStatus"
	finalReasonAttr = "_ExitReason"
)

// MarshalFinal encodes the Final message: the starter's final job ad plus the
// raw waitpid status and JOB_* reason (exit.h codes, e.g. 100=JOB_EXITED).
func MarshalFinal(finalAd *classad.ClassAd, status, reason int) *classad.ClassAd {
	ad := classad.New()
	if finalAd != nil {
		for _, name := range finalAd.GetAttributes() {
			if expr, ok := finalAd.Lookup(name); ok {
				ad.InsertExpr(name, expr)
			}
		}
	}
	_ = ad.Set(finalStatusAttr, int64(status))
	_ = ad.Set(finalReasonAttr, int64(reason))
	return ad
}

// ParseFinal decodes MarshalFinal's ad, returning the final job ad (with the
// control attrs still present -- harmless) plus the status and reason.
func ParseFinal(ad *classad.ClassAd) (finalAd *classad.ClassAd, status, reason int) {
	if v, ok := ad.EvaluateAttrInt(finalStatusAttr); ok {
		status = int(v)
	}
	if v, ok := ad.EvaluateAttrInt(finalReasonAttr); ok {
		reason = int(v)
	}
	return ad, status, reason
}
