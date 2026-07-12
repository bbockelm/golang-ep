package startd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/message"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/golang-htcondor/logging"

	"github.com/bbockelm/golang-ep/internal/adwire"
	"github.com/bbockelm/golang-ep/internal/claim"
	"github.com/bbockelm/golang-ep/internal/reconnect"
	"github.com/bbockelm/golang-ep/internal/slot"
	"github.com/bbockelm/golang-ep/internal/starter"
)

// ACTIVATE_CLAIM reply codes (condor_commands.h generic replies; mirror
// hstartd.Activate*).
const (
	activateNotOK    = 0 // refused
	activateOK       = 1 // accepted; this socket becomes the syscall channel
	activateTryAgain = 2 // CONDOR_TRY_AGAIN (transient; not used until Stage 8)
)

// --- Events (single-writer loop) ---

// activateDecision is the loop's answer to an ACTIVATE_CLAIM, handed back to
// the blocked handler. On accept it carries the startd-side transport the
// handler must PassSyscallConn the taken-over connection into.
type activateDecision struct {
	code      int
	transport starter.Transport
	slotName  string
}

// evActivateClaim asks the loop to validate an ACTIVATE_CLAIM and, on accept,
// spawn the starter. The handler blocks on reply.
type evActivateClaim struct {
	claimID string
	jobAd   *classad.ClassAd
	reply   chan activateDecision
}

// evStarterUpdate delivers a starter's periodic Update ad to the loop.
type evStarterUpdate struct {
	slotName string
	ad       *classad.ClassAd
}

// evStarterFinal delivers a starter's Final report to the loop.
type evStarterFinal struct {
	slotName string
	ad       *classad.ClassAd
	status   int
	reason   int
}

// evStarterExited reports that a starter's control channel finished (clean
// Exited message or channel breakage). Idempotent on the loop.
type evStarterExited struct{ slotName string }

// evStarterHello delivers a starter's Hello to the loop so it can record the
// starter's own command address (StarterIpAddr) for CA_LOCATE_STARTER and
// persist it.
type evStarterHello struct {
	slotName    string
	starterAddr string
	starterPid  int
	jobPid      int
}

// evLocateStarter answers a CA_LOCATE_STARTER: find the claim by GlobalJobId (or
// claim id) across live activations + persisted records and return its
// StarterIpAddr. The handler blocks on reply.
type evLocateStarter struct {
	claimID     string
	globalJobID string
	reply       chan reconnect.LocateResult
}

// evAdopt kicks off Stage-7 re-adoption on the loop: reconstruct claimed slots
// from the durable store, re-register match sessions, and redial surviving
// starters. done is closed when reconstruction (not the async redials) finishes.
type evAdopt struct{ done chan struct{} }

// evAdoptFailed fires when a re-adopted starter could not be redialed (it died
// while the startd was down): the loop reads the sandbox .exit marker to decide
// whether the job finished (apply outcome) or the claim is lost.
type evAdoptFailed struct{ slotName string }

// deactivateDecision is the loop's answer to a DEACTIVATE_CLAIM, handed back to
// the blocked handler so it can write the {Start: !closing} response ad.
type deactivateDecision struct {
	known    bool
	closing  bool // claim_is_closing: the claim will not be reused (MVP: false)
	slotName string
	// deferred (413 only): the starter is still running; the handler must wait on
	// wait (closed when the starter reaps) before replying.
	deferred bool
	wait     chan struct{}
}

// evDeactivate asks the loop to decide a DEACTIVATE_CLAIM (compute closing,
// arrange 413 deferral). The handler blocks on reply.
type evDeactivate struct {
	claimID string
	command int
	reply   chan deactivateDecision
}

// evVacate asks the loop to vacate a slot's running starter AFTER the deactivate
// reply has been flushed: soft (SIGTERM -> SIGKILL escalation) or hard (SIGKILL).
type evVacate struct {
	slotName string
	hard     bool
}

// evVacateEscalate fires when a soft vacate's max-vacate timer elapses without
// the starter exiting: escalate to a hard kill. Guarded on the same activation
// still running (the gen counter prevents a stale timer from killing a later
// activation on the same slot).
type evVacateEscalate struct {
	slotName string
	gen      int64
}

func (evActivateClaim) isEvent()  {}
func (evStarterUpdate) isEvent()  {}
func (evStarterFinal) isEvent()   {}
func (evStarterExited) isEvent()  {}
func (evStarterHello) isEvent()   {}
func (evLocateStarter) isEvent()  {}
func (evAdopt) isEvent()          {}
func (evAdoptFailed) isEvent()    {}
func (evDeactivate) isEvent()     {}
func (evVacate) isEvent()         {}
func (evVacateEscalate) isEvent() {}

// activation is the loop's record of a running starter. Touched only from the
// event loop.
type activation struct {
	cancel    context.CancelFunc
	transport starter.Transport
	vacateCh  chan int // control-message type to relay (MsgVacateHard/...)
	sandbox   string
	jobAd     *classad.ClassAd // activated job ad (for persistence)
	globalJID string           // the job's GlobalJobId (CA_LOCATE_STARTER key)

	// starterAddr is the process starter's own CA_CMD command sinful, learned
	// from its Hello (StarterIpAddr); CA_LOCATE_STARTER answers with it.
	starterAddr string

	// Process-mode fields (nil/zero for goroutine mode).
	starterCmd *exec.Cmd     // the spawned condor_starter process
	starterPid int           // its pid (persisted, logged)
	socketPath string        // its control socket (persisted; Stage-7 redial)
	reaped     chan struct{} // closed by reapStarter once cmd.Wait returns

	// adopted marks an activation reconstructed by re-adoption (Stage 7) rather
	// than a fresh spawn: no exec.Cmd is owned (the surviving starter's real
	// parent is gone), so reap/kill backstops are skipped.
	adopted bool

	// gen uniquely identifies this activation on its slot so a soft-vacate
	// escalation timer that fires after the starter already exited (and a new
	// activation possibly started) is ignored. Set from c.activationGen.
	gen int64
	// vacating marks that a soft/hard vacate is in progress (suppresses the
	// escalation timer once the starter is confirmed gone).
	vacating bool
}

// --- Command handlers (cedar server goroutines) ---

// handleActivateClaim serves ACTIVATE_CLAIM=444 (command.cpp:188,1739). Wire
// in: get_secret(claim id) + code(int legacy starter version, ignored) +
// getClassAd(job ad) + EOM. The accept/reject decision comes from the event
// loop. Per the C++ startd the OK reply is written BEFORE the starter runs;
// then the SAME socket becomes the starter<->shadow remote-syscall channel:
// the handler hands conn.Stream (buffered data + AES session state intact) to
// the starter via the transport and returns cedarserver.KeepOpen() so the
// server never closes the connection out from under the starter.
func (c *Core) handleActivateClaim(ctx context.Context, conn *cedarserver.Conn) error {
	in := conn.Message
	if in == nil {
		in = message.NewMessageFromStream(conn.Stream)
	}
	claimID, err := in.GetString(ctx)
	if err != nil {
		return err
	}
	if _, err := in.GetInt(ctx); err != nil { // legacy starter version; ignored
		return err
	}
	// The real C++ shadow's job ad carries PRIVATE attributes (ClaimId,
	// TransferKey, ...) which putClassAd serializes with the SECRET_MARKER wire
	// form; cedar's GetClassAd cannot decode that, so we use our own
	// secrets-aware reader (adwire).
	jobAd, err := adwire.GetClassAd(ctx, in, func(attr string, perr error) {
		c.log.Warn(logging.DestinationGeneral, "ACTIVATE_CLAIM: skipping unparseable job-ad attribute",
			"attr", attr, "err", perr.Error())
	})
	if err != nil {
		c.log.Warn(logging.DestinationGeneral, "ACTIVATE_CLAIM: reading job ad failed", "err", err.Error())
		return err
	}

	reply := make(chan activateDecision, 1)
	c.Submit(evActivateClaim{claimID: claimID, jobAd: jobAd, reply: reply})

	var dec activateDecision
	select {
	case dec = <-reply:
	case <-ctx.Done():
		return ctx.Err()
	}

	out := message.NewMessageForStream(conn.Stream)
	if err = out.PutInt(ctx, dec.code); err == nil {
		err = out.FinishMessage(ctx)
	} else {
		_ = out.FinishMessage(ctx)
	}
	if err != nil {
		// Accepted but the reply never made it: tear the activation down so the
		// slot does not wedge in Claimed/Busy with a starter awaiting a syscall
		// conn that will never come.
		if dec.code == activateOK {
			c.Submit(evStarterExited{slotName: dec.slotName})
		}
		return err
	}
	if dec.code != activateOK {
		return nil
	}

	// Socket takeover: the conn's Stream (with its claim-session encryption
	// state) becomes the starter's remote-syscall channel.
	if err := dec.transport.PassSyscallConn(conn.Stream); err != nil {
		c.Submit(evStarterExited{slotName: dec.slotName})
		return err
	}
	return cedarserver.KeepOpen()
}

// handleDeactivateClaim serves the DEACTIVATE_CLAIM variants (command.cpp:92-185):
//   - 403 DEACTIVATE_CLAIM (graceful): soft vacate (SIGTERM -> SIGKILL escalation)
//   - 404 DEACTIVATE_CLAIM_FORCIBLY: hard vacate (SIGKILL now)
//   - 413 DEACTIVATE_CLAIM_JOB_DONE: the starter is already exiting; do NOT kill.
//     If it is still alive, STASH the reply and answer only after it reaps
//     (KeepStream); if already gone, reply immediately.
//   - 561 DEACTIVATE_CLAIM_FINAL_XFER: treated as graceful here.
//
// In every case the response ClassAd {Start: !claim_is_closing} is written
// BEFORE the starter is killed (the C++ deadlock-avoidance ordering): the loop
// decides claim_is_closing and whether to defer, the handler flushes the reply,
// and only then (403/404) does a second event trigger the actual vacate.
func (c *Core) handleDeactivateClaim(ctx context.Context, conn *cedarserver.Conn) error {
	in := conn.Message
	if in == nil {
		in = message.NewMessageFromStream(conn.Stream)
	}
	claimID, err := in.GetString(ctx)
	if err != nil {
		return err
	}

	reply := make(chan deactivateDecision, 1)
	c.Submit(evDeactivate{claimID: claimID, command: conn.Command, reply: reply})
	var dec deactivateDecision
	select {
	case dec = <-reply:
	case <-ctx.Done():
		return ctx.Err()
	}

	// 413 with a still-running starter: wait for it to reap before replying
	// (the stream is "stashed" -- we simply block the handler goroutine holding
	// the conn until the loop signals the reap).
	if dec.deferred {
		select {
		case <-dec.wait:
		case <-ctx.Done():
			return ctx.Err()
		}
		// Recompute closing after the reap is irrelevant for MVP; reuse dec.closing.
	}

	c.log.Info(logging.DestinationGeneral, "DEACTIVATE_CLAIM",
		"command", conn.Command, "claim_known", dec.known, "closing", dec.closing,
		"deferred", dec.deferred, "slot", dec.slotName)

	respAd := classad.New()
	_ = respAd.Set("Start", !dec.closing)
	out := message.NewMessageForStream(conn.Stream)
	if err := out.PutClassAd(ctx, respAd); err != nil {
		return err
	}
	if err := out.FinishMessage(ctx); err != nil {
		return err
	}

	// Reply flushed: NOW trigger the vacate (403 soft / 404 hard). 413 never
	// kills (the starter is exiting on its own); an unknown claim has nothing to
	// do.
	if dec.known && !dec.deferred &&
		(conn.Command == claim.CmdDeactivateClaim ||
			conn.Command == claim.CmdDeactivateClaimForcibly ||
			conn.Command == claim.CmdDeactivateFinalXfer) {
		hard := conn.Command == claim.CmdDeactivateClaimForcibly
		c.Submit(evVacate{slotName: dec.slotName, hard: hard})
	}
	return nil
}

// --- Event-loop transition handlers ---

// doActivateClaim validates an ACTIVATE_CLAIM (command.cpp:1831 semantics) and,
// on accept, builds the goroutine transport pair, spawns the starter and its
// supervisor, and moves the slot to Claimed/Busy. The handler gets the
// transport back so it can reply OK first and then pass the socket.
func (c *Core) doActivateClaim(ctx context.Context, ev evActivateClaim) {
	reject := func(why string) {
		c.log.Info(logging.DestinationGeneral, "ACTIVATE_CLAIM rejected: "+why)
		ev.reply <- activateDecision{code: activateNotOK}
	}

	s := c.findSlotByClaimID(ev.claimID)
	if s == nil {
		reject("unknown claim id")
		return
	}
	cl := s.Claim()
	if cl == nil || !cl.State().IsClaimed() {
		reject("slot not Claimed (slot " + s.Name + ")")
		return
	}
	if cl.State() != claim.ClaimedIdle {
		// Already Busy (or, later, mid-deactivation -> TRY_AGAIN per C++).
		reject("slot not Claimed/Idle (slot " + s.Name + ")")
		return
	}
	if _, ok := ev.jobAd.EvaluateAttrInt("JobUniverse"); !ok {
		reject("job ad has no JobUniverse")
		return
	}
	// Re-evaluate the machine Requirements against the job ad. The claimed
	// slot ADVERTISES Requirements=false (so it never re-matches), so this must
	// use the unclaimed-form MatchAd (Start && WithinResourceLimits) -- see
	// slot.MatchAd.
	matchAd := s.MatchAd()
	matchAd.SetTarget(ev.jobAd)
	if ok, isBool := matchAd.EvaluateAttrBool("Requirements"); !isBool || !ok {
		reject("machine Requirements not satisfied by job (slot " + s.Name + ")")
		return
	}
	if c.executeDir == "" {
		reject("no EXECUTE directory configured")
		return
	}

	// Fresh sandbox under EXECUTE: unique per activation.
	c.sandboxSeq++
	sandbox := filepath.Join(c.executeDir,
		fmt.Sprintf("dir_%d_slot%d_%d", os.Getpid(), s.SlotID, c.sandboxSeq))
	if err := os.MkdirAll(sandbox, 0o700); err != nil {
		reject("creating sandbox: " + err.Error())
		return
	}

	actx, cancel := context.WithCancel(ctx)
	slotName := s.Name
	c.activationGen++
	act := &activation{
		cancel:    cancel,
		vacateCh:  make(chan int, 1),
		sandbox:   sandbox,
		jobAd:     ev.jobAd,
		globalJID: adString(ev.jobAd, "GlobalJobId"),
		gen:       c.activationGen,
	}
	activateMsg := &starter.ActivateMsg{
		JobAd:      ev.jobAd,
		SlotAd:     s.PublicAd(),
		SandboxDir: sandbox,
	}

	// STARTER_MODE decides how the starter runs: an in-process goroutine
	// (default) or a separate condor_starter process the startd spawns, dials
	// over a per-claim Unix socket, and hands the syscall connection to via
	// SCM_RIGHTS. The Transport interface makes the supervisor path identical.
	if c.starterMode == starterModeProcess {
		sockPath, err := c.starterSocketPath(cl.PublicClaimID())
		if err != nil {
			cancel()
			reject("allocating starter socket path: " + err.Error())
			return
		}
		cmd := c.buildStarterCmd(sockPath, sandbox, slotName, cl.PublicClaimID())
		if err := cmd.Start(); err != nil {
			cancel()
			reject("spawning starter process: " + err.Error())
			return
		}
		act.transport = starter.NewUnixStartd(sockPath)
		act.starterCmd = cmd
		act.starterPid = cmd.Process.Pid
		act.socketPath = sockPath
		act.reaped = make(chan struct{})
		c.activations[slotName] = act
		go c.reapStarter(slotName, cmd, act.reaped)
	} else {
		startdT, starterT := starter.NewInprocPair()
		act.transport = startdT
		c.activations[slotName] = act
		go func() {
			if err := starter.Run(actx, starterT, starter.Options{
				Logger:           c.log,
				SlotName:         slotName,
				ClaimID:          cl.PublicClaimID(),
				UpdateInterval:   c.starterUpdate,
				UIDDomain:        c.uidDomain,
				FileSystemDomain: c.fsDomain,
			}); err != nil {
				c.log.Warn(logging.DestinationGeneral, "starter run ended with error",
					"slot", slotName, "err", err.Error())
			}
		}()
	}

	go c.superviseStarter(actx, slotName, act, activateMsg, false)

	now := time.Now()
	cl.SetBusy(now)
	s.SetStateActivity("Claimed", "Busy", now)
	c.persistSlot(s)
	c.log.Info(logging.DestinationGeneral, "ACTIVATE_CLAIM accepted",
		"slot", s.Name, "sandbox", sandbox, "mode", c.starterMode,
		"starter_pid", act.starterPid, "public_claim", cl.PublicClaimID())

	ev.reply <- activateDecision{code: activateOK, transport: act.transport, slotName: s.Name}
	c.reAdvertise(ctx)
}

// reapStarter waits on a process-mode starter and turns its exit into an
// evStarterExited event. A process death WITHOUT a preceding clean Exited
// message (e.g. kill -9) still funnels through here, so the slot recovers to
// Claimed/Idle either way. reaped is closed first so killActivation's SIGKILL
// backstop does not fire on (or race) an already-reaped pid.
func (c *Core) reapStarter(slotName string, cmd *exec.Cmd, reaped chan struct{}) {
	err := cmd.Wait()
	close(reaped)
	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}
	c.log.Info(logging.DestinationGeneral, "process starter reaped",
		"slot", slotName, "pid", pid, "wait_err", errString(err))
	c.Submit(evStarterExited{slotName: slotName})
}

// starterSocketPath returns a SHORT per-activation Unix socket path under the
// configured starter socket dir. macOS caps sun_path near 104 bytes, so we hash
// the public claim id + activation sequence to a compact name rather than
// embedding the (long) claim id.
func (c *Core) starterSocketPath(publicClaimID string) (string, error) {
	if c.starterSocketDir == "" {
		return "", fmt.Errorf("no starter socket dir configured (set EP_STARTER_SOCKET_DIR or SPOOL)")
	}
	if err := os.MkdirAll(c.starterSocketDir, 0o700); err != nil {
		return "", fmt.Errorf("creating starter socket dir: %w", err)
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d", publicClaimID, c.sandboxSeq)))
	return filepath.Join(c.starterSocketDir, hex.EncodeToString(sum[:8])+".sock"), nil
}

// buildStarterCmd assembles the exec.Cmd for a process-mode starter: the
// STARTER binary with the socket/slot/claim/sandbox and update/domain flags, and
// its own log under the sandbox. The startd owns the process (reaps + kills it);
// the starter owns the job's process group.
func (c *Core) buildStarterCmd(sockPath, sandbox, slotName, publicClaimID string) *exec.Cmd {
	// The starter log MUST live outside the sandbox: the job's output-transfer
	// sweep ships everything in the sandbox, and a log the starter is still
	// writing would corrupt that transfer. Park it next to the control socket.
	logPath := strings.TrimSuffix(sockPath, ".sock") + ".starterlog"
	args := []string{
		"-socket", sockPath,
		"-slot", slotName,
		"-claim", publicClaimID,
		"-sandbox", sandbox,
		"-log", logPath,
	}
	if c.starterUpdate > 0 {
		args = append(args, "-update-interval", strconv.Itoa(int(c.starterUpdate.Seconds())))
	}
	if c.uidDomain != "" {
		args = append(args, "-uid-domain", c.uidDomain)
	}
	if c.fsDomain != "" {
		args = append(args, "-fs-domain", c.fsDomain)
	}
	return exec.Command(c.starterPath, args...)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// superviseStarter owns the startd's side of one starter's control channel: it
// sends Activate, relays vacate requests from the loop, and turns the
// starter's Hello/Update/Final/Exited into loop events. It is the only WRITER
// on the startd's control end (a dedicated sub-goroutine is the only reader),
// so pipe-backed control cannot deadlock.
func (c *Core) superviseStarter(ctx context.Context, slotName string, act *activation, msg *starter.ActivateMsg, reattach bool) {
	exited := func() { c.Submit(evStarterExited{slotName: slotName}) }
	// On the re-adoption path a redial/Reattach failure means the surviving
	// starter is gone: run the .exit-marker recovery instead of the normal
	// starter-exited wind-down.
	giveUp := func() {
		if reattach {
			c.Submit(evAdoptFailed{slotName: slotName})
		} else {
			exited()
		}
	}

	// Establish the control channel (process mode dials the starter's socket with
	// bounded retry; goroutine mode is a no-op). On re-adoption this dials the
	// SURVIVING starter's listening socket.
	if err := act.transport.Connect(ctx); err != nil {
		c.log.Warn(logging.DestinationGeneral, "connecting to starter failed",
			"slot", slotName, "reattach", reattach, "err", err.Error())
		giveUp()
		return
	}
	ctrl := act.transport.Control()

	if reattach {
		// Re-adoption: the job is already running and the syscall socket already
		// lives in the surviving starter, so we send Reattach (not Activate) and do
		// NOT hand over a syscall conn. The starter replies with a fresh Hello.
		if err := starter.WriteMessage(ctx, ctrl, starter.MsgReattach, nil); err != nil {
			c.log.Warn(logging.DestinationGeneral, "sending Reattach to surviving starter failed",
				"slot", slotName, "err", err.Error())
			giveUp()
			return
		}
		c.log.Info(logging.DestinationGeneral, "re-adopted starter: Reattach sent, awaiting Hello",
			"slot", slotName, "socket", act.socketPath)
	} else {
		if err := starter.WriteMessage(ctx, ctrl, starter.MsgActivate, starter.MarshalActivate(msg)); err != nil {
			c.log.Warn(logging.DestinationGeneral, "sending Activate to starter failed",
				"slot", slotName, "err", err.Error())
			exited()
			return
		}

		// Complete the syscall-conn handoff (process mode: SyscallConnFollows + the
		// SCM_RIGHTS fd pass, serialized right after Activate on this one writer;
		// goroutine mode: a no-op, PassSyscallConn already delivered the pointer).
		if err := act.transport.FinishActivation(ctx); err != nil {
			c.log.Warn(logging.DestinationGeneral, "handing syscall conn to starter failed",
				"slot", slotName, "err", err.Error())
			exited()
			return
		}
	}

	msgs := make(chan struct {
		typ int
		ad  *classad.ClassAd
	}, 8)
	go func() {
		defer close(msgs)
		for {
			typ, ad, err := starter.ReadMessage(ctx, ctrl)
			if err != nil {
				return
			}
			select {
			case msgs <- struct {
				typ int
				ad  *classad.ClassAd
			}{typ, ad}:
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case typ := <-act.vacateCh:
			if err := starter.WriteMessage(ctx, ctrl, typ, nil); err != nil {
				c.log.Debug(logging.DestinationGeneral, "relaying vacate to starter failed",
					"slot", slotName, "err", err.Error())
			}
		case m, ok := <-msgs:
			if !ok {
				exited()
				return
			}
			switch m.typ {
			case starter.MsgHello:
				h := starter.ParseHello(m.ad)
				c.log.Info(logging.DestinationGeneral, "starter hello",
					"slot", slotName, "starter_pid", h.StarterPid, "job_pid", h.JobPid,
					"starter_ip_addr", h.StarterAddr, "phase", h.Phase)
				c.Submit(evStarterHello{
					slotName:    slotName,
					starterAddr: h.StarterAddr,
					starterPid:  h.StarterPid,
					jobPid:      h.JobPid,
				})
			case starter.MsgUpdate:
				c.Submit(evStarterUpdate{slotName: slotName, ad: m.ad})
			case starter.MsgFinal:
				fad, status, reason := starter.ParseFinal(m.ad)
				c.Submit(evStarterFinal{slotName: slotName, ad: fad, status: status, reason: reason})
			case starter.MsgExited:
				exited()
				return
			default:
				c.log.Debug(logging.DestinationGeneral, "unknown starter control message",
					"slot", slotName, "msg", starter.MsgName(m.typ))
			}
		case <-ctx.Done():
			// The reader goroutine will fail and close msgs; evStarterExited is
			// idempotent, so submit and go.
			exited()
			return
		}
	}
}

// doStarterHello records the starter's own command address (StarterIpAddr) from
// its Hello so CA_LOCATE_STARTER can direct a reconnecting shadow to it, and
// persists it (a restarted startd answers CA_LOCATE_STARTER from the store even
// before the surviving starter re-Hellos).
func (c *Core) doStarterHello(ev evStarterHello) {
	act := c.activations[ev.slotName]
	if act == nil {
		return
	}
	changed := false
	if ev.starterAddr != "" && act.starterAddr != ev.starterAddr {
		act.starterAddr = ev.starterAddr
		changed = true
	}
	if ev.starterPid != 0 && act.starterPid != ev.starterPid {
		// A re-adopted starter reports its real pid (we did not spawn it).
		act.starterPid = ev.starterPid
		changed = true
	}
	if changed {
		if s := c.byName[ev.slotName]; s != nil {
			c.persistSlot(s)
		}
	}
}

// doLocateStarter answers a CA_LOCATE_STARTER lookup from live activations first,
// then the durable store (a surviving starter whose startd just restarted may
// not have re-Hello'd yet, but its address is on disk).
func (c *Core) doLocateStarter(claimID, globalJobID string) reconnect.LocateResult {
	match := func(recClaim, recGJID string) bool {
		if globalJobID != "" && recGJID == globalJobID {
			return true
		}
		return claimID != "" && recClaim == claimID
	}
	// Live: match by claim id (via the slot's current claim) or GlobalJobId.
	for slotName, act := range c.activations {
		gjMatch := globalJobID != "" && act.globalJID == globalJobID
		cidMatch := false
		if claimID != "" {
			if s := c.byName[slotName]; s != nil {
				if cl := s.Claim(); cl != nil && cl.ClaimID() == claimID {
					cidMatch = true
				}
			}
		}
		if (gjMatch || cidMatch) && act.starterAddr != "" {
			return reconnect.LocateResult{Found: true, StarterAddr: act.starterAddr}
		}
	}
	// Persisted fallback.
	if c.store != nil {
		for _, rec := range c.store.List() {
			if match(rec.ClaimID, rec.GlobalJobID) {
				return reconnect.LocateResult{Found: true, StarterAddr: rec.StarterIpAddr}
			}
		}
	}
	return reconnect.LocateResult{}
}

// doStarterUpdate stores the starter's latest Update ad on the claim record.
func (c *Core) doStarterUpdate(ev evStarterUpdate) {
	s := c.byName[ev.slotName]
	if s == nil {
		return
	}
	if cl := s.Claim(); cl != nil && cl.State().IsClaimed() {
		cl.SetUpdateAd(ev.ad)
	}
}

// doStarterFinal stores the starter's Final report on the claim record (used
// by later stages; Stage 3 just retains it).
func (c *Core) doStarterFinal(ev evStarterFinal) {
	s := c.byName[ev.slotName]
	if s == nil {
		return
	}
	if cl := s.Claim(); cl != nil && cl.State().IsClaimed() {
		cl.SetFinal(ev.ad, ev.status, ev.reason)
		c.log.Info(logging.DestinationGeneral, "starter final report",
			"slot", ev.slotName, "status", ev.status, "reason", ev.reason)
	}
}

// doStarterExited winds down an activation: cancel the starter, close the
// transport, and -- when the claim survived (normal job completion) -- return
// the slot to Claimed/Idle (the schedd decides the next move, per C++
// semantics). Idempotent: a second Exited for the same activation (or one
// racing a release) finds no activation record and no-ops.
func (c *Core) doStarterExited(ctx context.Context, slotName string) {
	act := c.activations[slotName]
	if act == nil {
		// The activation is already gone, but a 413 reply may still be stashed
		// (e.g. two Exited events race): release it so the handler unblocks.
		c.releaseDeferredDeactivate(slotName)
		return
	}
	delete(c.activations, slotName)
	act.cancel()
	_ = act.transport.Close()

	// A stashed DEACTIVATE_CLAIM_JOB_DONE (413) reply waits for this reap: signal
	// it so the handler sends {Start: !closing} now (command.cpp KEEP_STREAM).
	c.releaseDeferredDeactivate(slotName)

	s := c.byName[slotName]
	if s == nil {
		return
	}
	if cl := s.Claim(); cl != nil && cl.State() == claim.ClaimedBusy {
		now := time.Now()
		cl.SetIdle(now)
		s.SetStateActivity("Claimed", "Idle", now)
		c.persistSlot(s)
		c.log.Info(logging.DestinationGeneral, "starter exited; slot back to Claimed/Idle",
			"slot", slotName)
		c.reAdvertise(ctx)
	}
}

// releaseDeferredDeactivate closes and clears a slot's stashed 413 reply channel
// (if any), unblocking the DEACTIVATE_CLAIM_JOB_DONE handler to send its reply.
// Loop-only; safe if none is stashed.
func (c *Core) releaseDeferredDeactivate(slotName string) {
	if ch := c.deferredDeactivate[slotName]; ch != nil {
		close(ch)
		delete(c.deferredDeactivate, slotName)
	}
}

// killActivation tears down a running starter during a release (PROVISIONAL
// Stage-3 semantics; Stage 8 brings graceful vacate): best-effort VacateHard
// via the supervisor, then cancel the starter's context (which hard-kills the
// job's process group) and close the transport. Loop-only.
func (c *Core) killActivation(slotName, reason string) {
	act := c.activations[slotName]
	if act == nil {
		return
	}
	delete(c.activations, slotName)
	c.log.Info(logging.DestinationGeneral, "killing running starter",
		"slot", slotName, "reason", reason)
	select {
	case act.vacateCh <- starter.MsgVacateHard:
	default:
	}
	act.cancel()
	_ = act.transport.Close()

	// Process mode: closing the control transport makes the starter observe the
	// broken channel and hard-vacate its job; but back it with a SIGKILL of the
	// STARTER pid after KILLING_TIMEOUT in case it wedged. reaped short-circuits
	// the backstop (and prevents killing a recycled pid) once cmd.Wait returned.
	if act.starterCmd != nil && act.starterCmd.Process != nil {
		cmd := act.starterCmd
		reaped := act.reaped
		timeout := c.killingTimeout
		go func() {
			t := time.NewTimer(timeout)
			defer t.Stop()
			select {
			case <-reaped:
			case <-t.C:
				_ = cmd.Process.Kill()
			}
		}()
	}
}

// doDeactivate decides a DEACTIVATE_CLAIM on the loop (command.cpp:92-185):
// find the slot, compute claim_is_closing, and for 413 (job-done) arrange to
// defer the reply until the (still-running) starter reaps. The actual vacate
// for 403/404 is triggered by the handler AFTER it flushes the reply (evVacate),
// preserving the reply-before-kill ordering. Loop-only.
func (c *Core) doDeactivate(ev evDeactivate) {
	s := c.findSlotByClaimID(ev.claimID)
	if s == nil {
		// Unknown/closed claim: C++ still replies (Start:false).
		ev.reply <- deactivateDecision{known: false, closing: true}
		return
	}
	closing := c.claimIsClosing(s)
	act := c.activations[s.Name]

	if ev.command == claim.CmdDeactivateClaimJobDone {
		if act != nil {
			// Starter still running: stash the reply until it reaps. Do NOT kill.
			wait := make(chan struct{})
			c.deferredDeactivate[s.Name] = wait
			ev.reply <- deactivateDecision{known: true, closing: closing, slotName: s.Name, deferred: true, wait: wait}
			return
		}
		ev.reply <- deactivateDecision{known: true, closing: closing, slotName: s.Name}
		return
	}

	ev.reply <- deactivateDecision{known: true, closing: closing, slotName: s.Name}
}

// claimIsClosing reports whether a claim will NOT be reused after deactivation
// (command.cpp:116-127: preempting/retiring/draining/worklife-expired). MVP: a
// claim is kept for reuse (returns false) so a deactivated slot returns to
// Claimed/Idle. Kept as a hook for later preemption/worklife logic.
func (c *Core) claimIsClosing(s *slot.Slot) bool { return false }

// doVacate vacates a slot's running starter after the DEACTIVATE reply was
// flushed: hard = SIGKILL now; soft = SIGTERM with a SIGKILL escalation timer
// (max-vacate). Loop-only.
func (c *Core) doVacate(ctx context.Context, ev evVacate) {
	act := c.activations[ev.slotName]
	if act == nil {
		return // starter already gone; nothing to vacate
	}
	act.vacating = true
	if ev.hard {
		c.log.Info(logging.DestinationGeneral, "DEACTIVATE: hard vacate (SIGKILL)", "slot", ev.slotName)
		select {
		case act.vacateCh <- starter.MsgVacateHard:
		default:
		}
		return
	}
	c.log.Info(logging.DestinationGeneral, "DEACTIVATE: soft vacate (SIGTERM), escalating after max-vacate",
		"slot", ev.slotName, "max_vacate", c.maxVacateTime.String())
	select {
	case act.vacateCh <- starter.MsgVacateSoft:
	default:
	}
	// Escalation: if the starter has not reaped within maxVacateTime, escalate to
	// a hard kill. The gen guard makes a stale timer (starter exited, new
	// activation started) a no-op.
	gen := act.gen
	slotName := ev.slotName
	timeout := c.maxVacateTime
	go func() {
		t := time.NewTimer(timeout)
		defer t.Stop()
		select {
		case <-ctx.Done():
		case <-t.C:
			c.Submit(evVacateEscalate{slotName: slotName, gen: gen})
		}
	}()
}

// doVacateEscalate escalates a soft vacate to a hard kill when the max-vacate
// timer elapsed and the SAME activation is still running. Loop-only.
func (c *Core) doVacateEscalate(ev evVacateEscalate) {
	act := c.activations[ev.slotName]
	if act == nil || act.gen != ev.gen {
		return // starter already reaped (or a newer activation) -- stale timer
	}
	c.log.Warn(logging.DestinationGeneral, "soft vacate max-vacate expired; escalating to SIGKILL",
		"slot", ev.slotName)
	select {
	case act.vacateCh <- starter.MsgVacateHard:
	default:
	}
}
