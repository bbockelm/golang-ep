package starter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/stream"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/syscalls"

	"github.com/bbockelm/golang-ep/internal/adwire"
)

// getJobInfoWithSecrets performs CONDOR_get_job_info (op -63) directly on the
// syscall stream and reads the reply job ad with the SECRET_MARKER-aware reader.
// It mirrors syscalls.Client.GetJobInfo's framing (PutInt(op)+EOM; reply
// rval[+terrno] then the ad, drained to EOM) but substitutes adwire.GetClassAd
// for cedar's GetClassAd so the C++ shadow's private job-ad attributes decode.
func getJobInfoWithSecrets(ctx context.Context, st *stream.Stream, log *logging.Logger) (*classad.ClassAd, error) {
	out := message.NewMessageForStream(st)
	if err := out.PutInt(ctx, syscalls.OpGetJobInfo); err != nil {
		return nil, fmt.Errorf("writing op: %w", err)
	}
	if err := out.FinishMessage(ctx); err != nil {
		return nil, fmt.Errorf("flushing request: %w", err)
	}
	in := message.NewMessageFromStream(st)
	rval, err := in.GetInt(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading rval: %w", err)
	}
	if rval < 0 {
		terrno, _ := in.GetInt(ctx)
		_ = drainMessage(ctx, in)
		return nil, fmt.Errorf("shadow declined get_job_info: rval=%d errno=%d", rval, terrno)
	}
	ad, err := adwire.GetClassAd(ctx, in, func(attr string, perr error) {
		if log != nil {
			log.Warn(logging.DestinationGeneral, "get_job_info: skipping unparseable job-ad attribute",
				"attr", attr, "err", perr.Error())
		}
	})
	if err != nil {
		return nil, fmt.Errorf("reading ad: %w", err)
	}
	_ = drainMessage(ctx, in)
	return ad, nil
}

// DefaultUpdateInterval is the periodic Update / register_job_info cadence
// (STARTER_UPDATE_INTERVAL's stock default).
const DefaultUpdateInterval = 300 * time.Second

// starterCondorVersion is the CondorVersion the starter reports in
// register_starter_info so the C++ shadow can set a valid FileTransfer peer
// version. It is deliberately a real, parseable, modern HTCondor version (the
// same 25.0.0 the golang-ap shadow's proven interop uses) rather than the
// golang-htcondor build version (often "dev"), which CondorVersionInfo cannot
// parse. Kept below 25.3 so the shadow uses the plain (non-delayed-attr) upload
// path that filetransfer.ReceiveStream implements.
const starterCondorVersion = "$CondorVersion: 25.0.0 2025-01-01 BuildID: golang-ep $"

// finalizeTimeout bounds the last-gasp sequence (job_exit to the shadow,
// Final+Exited to the startd) when the run context is already dead, so an
// aborted starter can still report before winding down.
const finalizeTimeout = 10 * time.Second

// Options configures a starter run. The same Options drive goroutine mode
// (Stage 3) and process mode (Stage 6): Run never assumes it shares an address
// space with the startd.
type Options struct {
	// Logger receives the starter's log lines. Nil gets a default logger.
	Logger *logging.Logger
	// SlotName is the claimed slot's name, advertised to the shadow in the
	// register_starter_info ad.
	SlotName string
	// ClaimID is the PUBLIC (secret-elided) claim id, sent in Hello for
	// correlation. Never pass the secret form.
	ClaimID string
	// UpdateInterval is the periodic Update/register_job_info cadence
	// (STARTER_UPDATE_INTERVAL). <=0 uses DefaultUpdateInterval.
	UpdateInterval time.Duration
	// UIDDomain / FileSystemDomain seed the register_starter_info ad. The
	// golang-ap shadow stores the ad without validating these, so hostname-ish
	// defaults are fine; empty omits them.
	UIDDomain        string
	FileSystemDomain string
	// OnFinal, if set, is invoked exactly once with the job's terminal outcome
	// (raw waitpid status, JOB_* reason from exit.h, and the final job ad) just
	// before the starter winds down -- on every exit path (normal, exec failure,
	// transfer failure, vacate). The process-mode starter uses it to drop the
	// sandbox .exit marker Stage-7 restart recovery reads.
	OnFinal func(status, reason int, finalAd *classad.ClassAd)

	// EnableCommandServer starts the starter's OWN cedar CA_CMD command port
	// (Stage 7): its sinful is advertised as StarterIpAddr and it serves
	// CA_RECONNECT_JOB so a reconnecting shadow can re-attach to the running job
	// after a startd restart or a startd-down-past-lease gap. Set only in process
	// mode (a goroutine starter dies with the startd, so it cannot survive to be
	// reconnected). Goroutine mode leaves it false.
	EnableCommandServer bool
	// CommandBindAddr is the TCP bind address for the command server
	// (default 127.0.0.1:0). Used only when EnableCommandServer is set.
	CommandBindAddr string
}

// ctrlMsg is one decoded control-channel message.
type ctrlMsg struct {
	typ int
	ad  *classad.ClassAd
}

// Run is the starter: it receives the Activate message and the syscall
// connection over the transport, performs the shadow handshake (get_job_info,
// register_starter_info, get_sec_session_info, begin_execution), executes the
// job in the sandbox, streams periodic updates, and finishes with job_exit to
// the shadow plus Final+Exited to the startd. It returns after the final
// sequence; cancel ctx to hard-kill the job (the release/vacate path).
//
// Error contract: an error return means the run aborted on an infrastructure
// failure (transport/syscall breakage). Job-level failures -- including exec
// failure -- are reported via job_exit/Final and return nil.
func Run(ctx context.Context, t StarterSide, opts Options) error {
	log := opts.Logger
	if log == nil {
		log, _ = logging.New(nil)
	}
	updateInterval := opts.UpdateInterval
	if updateInterval <= 0 {
		updateInterval = DefaultUpdateInterval
	}
	defer func() { _ = t.Close() }()
	ctrl := t.Control()

	// Dedicated control reader: Run's goroutine is the only control WRITER and
	// this goroutine the only READER, so pipe-backed control never deadlocks
	// (both directions always have a consumer). Closes ctrlCh on any read
	// error (including the startd closing the transport).
	ctrlCh := make(chan ctrlMsg, 8)
	go func() {
		defer close(ctrlCh)
		for {
			typ, ad, err := ReadMessage(ctx, ctrl)
			if err != nil {
				return
			}
			select {
			case ctrlCh <- ctrlMsg{typ: typ, ad: ad}:
			case <-ctx.Done():
				return
			}
		}
	}()

	sendCtrl := func(cctx context.Context, typ int, ad *classad.ClassAd) {
		if err := WriteMessage(cctx, ctrl, typ, ad); err != nil {
			log.Debug(logging.DestinationGeneral, "starter control send failed",
				"msg", MsgName(typ), "err", err.Error())
		}
	}

	// (1) Await Activate on the control channel.
	var act *ActivateMsg
	select {
	case m, ok := <-ctrlCh:
		if !ok {
			return fmt.Errorf("starter: control channel closed before Activate")
		}
		if m.typ != MsgActivate {
			return fmt.Errorf("starter: first control message is %s, want Activate", MsgName(m.typ))
		}
		var err error
		if act, err = ParseActivate(m.ad); err != nil {
			return err
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	// (2) Receive the ACTIVATE_CLAIM connection: the remote-syscall channel.
	sysSt, err := t.SyscallConn(ctx)
	if err != nil {
		return fmt.Errorf("starter: receiving syscall conn: %w", err)
	}
	defer func() { _ = sysSt.Close() }()
	cli := syscalls.NewClient(sysSt)

	// (2a) Stage 7: start the starter's own CA_CMD command port (process mode
	// only). Its sinful becomes StarterIpAddr so a reconnecting shadow can reach
	// this starter directly, unaffected by a startd restart. The reconnect session
	// it must resume is registered after get_sec_session_info (below).
	var cmdSrv *commandServer
	var reconnectCh chan *reconnectHandoff
	starterAddr := ""
	if opts.EnableCommandServer {
		var cerr error
		cmdSrv, cerr = newCommandServer(ctx, opts.CommandBindAddr, log)
		if cerr != nil {
			log.Warn(logging.DestinationGeneral, "starting CA command server failed; reconnect disabled",
				"err", cerr.Error())
		} else {
			defer func() { _ = cmdSrv.Close() }()
			reconnectCh = cmdSrv.reconnectCh
			starterAddr = cmdSrv.Sinful()
			log.Info(logging.DestinationGeneral, "starter command server listening",
				"starter_ip_addr", starterAddr)
		}
	}

	// finalize is the every-exit-path reporter: job_exit to the shadow (the
	// run's last RPC), then Final+Exited on the control channel -- all
	// best-effort on a bounded context so a dead parent context or a vanished
	// peer cannot wedge the wind-down.
	finalize := func(status, reason int, finalAd *classad.ClassAd, sendJobExit bool) {
		fctx, fcancel := context.WithTimeout(context.WithoutCancel(ctx), finalizeTimeout)
		defer fcancel()
		if sendJobExit {
			if err := cli.JobExit(fctx, status, reason, finalAd); err != nil {
				log.Warn(logging.DestinationGeneral, "job_exit send failed",
					"reason", reason, "err", err.Error())
			}
		}
		sendCtrl(fctx, MsgFinal, MarshalFinal(finalAd, status, reason))
		sendCtrl(fctx, MsgExited, nil)
		if opts.OnFinal != nil {
			opts.OnFinal(status, reason, finalAd)
		}
	}

	// (3) get_job_info: the AUTHORITATIVE job ad (the Activate copy is
	// advisory, per the contract). The C++ shadow's reply carries PRIVATE
	// attributes (ClaimId, TransferKey, TransferSocket) in the SECRET_MARKER wire
	// form, so we read it with the secrets-aware reader rather than
	// syscalls.GetJobInfo (whose cedar GetClassAd cannot decode the marker).
	jobAd, err := getJobInfoWithSecrets(ctx, sysSt, log)
	if err != nil {
		finalize(0, syscalls.JobNotStarted, classad.New(), false)
		return fmt.Errorf("starter: get_job_info: %w", err)
	}

	sendCtrl(ctx, MsgHello, MarshalHello(&HelloMsg{
		StarterPid:  os.Getpid(),
		StarterAddr: starterAddr,
		ClaimID:     opts.ClaimID,
		Phase:       "activated",
	}))

	// (4) register_starter_info.
	starterAd := classad.New()
	_ = starterAd.Set("Name", opts.SlotName)
	_ = starterAd.Set("CondorScratchDir", act.SandboxDir)
	// HasReconnect advertises that this starter serves CA_RECONNECT_JOB on its own
	// command port (StarterIpAddr): the shadow keeps the job's lease and reconnects
	// instead of requeueing if the connection drops. Only true in process mode with
	// a live command server (Stage 7).
	_ = starterAd.Set("HasReconnect", starterAddr != "")
	if starterAddr != "" {
		_ = starterAd.Set("StarterIpAddr", starterAddr)
	}
	// CondorVersion (ATTR_VERSION) is LOAD-BEARING for file transfer: the C++
	// shadow reads it here to setPeerVersion for its FileTransfer object
	// (remoteresource.cpp:966). Omitting it logs "Can't determine starter version
	// for FileTransfer!" and the shadow falls back to a protocol variant that
	// does NOT send the xfer_info preamble our filetransfer.ReceiveStream expects,
	// wedging input transfer. We advertise a valid modern version so the shadow
	// speaks the go-ahead + xfer_info protocol the filetransfer package
	// implements.
	_ = starterAd.Set("CondorVersion", starterCondorVersion)
	if opts.UIDDomain != "" {
		_ = starterAd.Set("UidDomain", opts.UIDDomain)
	}
	if opts.FileSystemDomain != "" {
		_ = starterAd.Set("FileSystemDomain", opts.FileSystemDomain)
	}
	if err := cli.RegisterStarterInfo(ctx, starterAd); err != nil {
		finalize(0, syscalls.JobNotStarted, classad.New(), true)
		return fmt.Errorf("starter: register_starter_info: %w", err)
	}

	// (5) get_sec_session_info: the C++ starter calls it whenever
	// match-password security is active. A shadow without file transfer
	// configured DECLINES (rval<0), which is fine for a no-transfer job; only a
	// transport failure is fatal. With transfer configured the reply carries
	// the reconnect + filetrans session triplets the transfer client needs.
	secInfo, err := cli.GetSecSessionInfo(ctx)
	if err != nil {
		var se *syscalls.SyscallError
		if !errors.As(err, &se) {
			finalize(0, syscalls.JobNotStarted, classad.New(), true)
			return fmt.Errorf("starter: get_sec_session_info: %w", err)
		}
		secInfo = nil
		log.Debug(logging.DestinationGeneral,
			"shadow declined get_sec_session_info (no transfer sessions); continuing")
	}

	// Register the claim-derived reconnect session on the command server so an
	// inbound CA_RECONNECT_JOB from a reconnecting shadow resumes it. Without the
	// shadow's session material (no transfer configured) reconnect is unavailable.
	if cmdSrv != nil && secInfo != nil {
		if rerr := cmdSrv.RegisterReconnectSession(secInfo); rerr != nil {
			log.Warn(logging.DestinationGeneral, "registering reconnect session failed; reconnect disabled",
				"err", rerr.Error())
		} else {
			log.Debug(logging.DestinationGeneral, "reconnect session registered on command server")
		}
	}

	// (6) Input file transfer -- BEFORE begin_execution, matching the C++
	// sequence (jic_shadow: transfer completes, then begin_execution, then
	// exec). A transfer failure here is reported as job_exit(status=0,
	// reason=JOB_NOT_STARTED=108) -- our documented choice: the job never
	// started, and 108 is the generic pre-exec failure code (exit.h's
	// JOB_CXFER_* codes are checkpoint-transfer-specific). The run returns nil:
	// a job-level outcome, not an infrastructure error, so the slot un-wedges.
	logf := func(format string, args ...any) {
		log.Debug(logging.DestinationGeneral, fmt.Sprintf(format, args...))
	}
	var transfer *transferState
	if shouldTransfer(jobAd) {
		var terr error
		transfer, terr = setupTransfer(jobAd, act.SandboxDir, secInfo, logf)
		if terr == nil && transfer != nil {
			terr = transfer.downloadInput(ctx)
		}
		if terr != nil {
			log.Warn(logging.DestinationGeneral, "input file transfer failed", "err", terr.Error())
			ad := classad.New()
			_ = ad.Set("ExitBySignal", false)
			_ = ad.Set("TransferInputFailed", true)
			_ = ad.Set("TransferErrorString", terr.Error())
			finalize(0, syscalls.JobNotStarted, ad, true)
			return nil
		}
		// The executable was transferred into the sandbox as basename(Cmd)
		// (TransferExecutable defaults to true); run the sandbox copy, like the
		// C++ starter does.
		transferExe := true
		if v, ok := jobAd.EvaluateAttrBool("TransferExecutable"); ok {
			transferExe = v
		}
		if cmd, _ := jobAd.EvaluateAttrString("Cmd"); transfer != nil && transferExe && cmd != "" {
			sandboxCmd := filepath.Join(act.SandboxDir, filepath.Base(cmd))
			if _, statErr := os.Stat(sandboxCmd); statErr == nil {
				_ = jobAd.Set("Cmd", sandboxCmd)
			} else {
				log.Warn(logging.DestinationGeneral,
					"TransferExecutable set but no sandbox copy arrived; running original Cmd",
					"cmd", cmd)
			}
		}
	}

	// (7) begin_execution: the last pre-exec syscall.
	if err := cli.BeginExecution(ctx); err != nil {
		finalize(0, syscalls.JobNotStarted, classad.New(), true)
		return fmt.Errorf("starter: begin_execution: %w", err)
	}

	// (8) Exec the job. An exec failure is a JOB outcome, not an infra error:
	// report job_exit(status=0, reason=JOB_EXEC_FAILED=110) -- our documented
	// choice over JOB_NOT_STARTED(108), which we reserve for pre-exec
	// infrastructure failures above.
	jp, err := startJob(jobAd, act, opts.SlotName)
	if err != nil {
		log.Warn(logging.DestinationGeneral, "job exec failed", "err", err.Error())
		ad := classad.New()
		_ = ad.Set("ExitBySignal", false)
		_ = ad.Set("ExecFailed", true)
		_ = ad.Set("ExecErrorString", err.Error())
		finalize(0, syscalls.JobExecFailed, ad, true)
		return nil
	}
	defer jp.killGroup()
	log.Info(logging.DestinationGeneral, "job started",
		"pid", jp.pid, "sandbox", act.SandboxDir, "slot", opts.SlotName)
	helloExecuting := func() *classad.ClassAd {
		return MarshalHello(&HelloMsg{
			StarterPid:  os.Getpid(),
			StarterAddr: starterAddr,
			ClaimID:     opts.ClaimID,
			JobPid:      jp.pid,
			Phase:       "executing",
		})
	}
	sendCtrl(ctx, MsgHello, helloExecuting())

	// (9) Monitor: waitpid + periodic updates + vacate handling.
	waitCh := make(chan error, 1)
	go func() { waitCh <- jp.cmd.Wait() }()
	ticker := time.NewTicker(updateInterval)
	defer ticker.Stop()

	vacated := false
	// reapAfterKill bounds the post-kill wait so a wedged child cannot hang
	// the starter forever.
	reapAfterKill := func() {
		select {
		case <-waitCh:
		case <-time.After(finalizeTimeout):
			log.Warn(logging.DestinationGeneral, "job did not reap after SIGKILL; abandoning wait")
		}
	}

	waitDone := false
	for !waitDone {
		select {
		case <-ctx.Done():
			// Release/shutdown: hard-kill the whole group and reap.
			vacated = true
			jp.killGroup()
			reapAfterKill()
			waitDone = true
		case m, ok := <-ctrlCh:
			if !ok {
				// Control channel gone: the startd abandoned us. Stage 3 has no
				// restart survival, so treat it as a hard vacate.
				vacated = true
				jp.killGroup()
				reapAfterKill()
				waitDone = true
				continue
			}
			switch m.typ {
			case MsgVacateHard:
				vacated = true
				jp.killGroup() // waitCh fires next
			case MsgVacateSoft:
				// Graceful vacate: SIGTERM the job's process group and let it shut
				// down on its own. We do NOT wait here -- waitCh fires when the job
				// exits; if it ignores SIGTERM, the startd escalates by sending
				// MsgVacateHard (SIGKILL) after its max-vacate timer. Mark vacated so
				// the final reason is JOB_KILLED and output transfer is skipped.
				v := ParseVacateSoft(m.ad)
				log.Info(logging.DestinationGeneral, "VacateSoft: SIGTERM job process group",
					"reason", v.Reason, "max_vacate", v.MaxVacateTime)
				vacated = true
				jp.termGroup()
			case MsgSuspend:
				log.Info(logging.DestinationGeneral, "Suspend: SIGSTOP job process group")
				jp.suspendGroup()
			case MsgContinue:
				log.Info(logging.DestinationGeneral, "Continue: SIGCONT job process group")
				jp.continueGroup()
			case MsgReattach:
				// A restarted startd redialed our (surviving) control socket and
				// re-adopted us. Re-announce ourselves so it re-learns our pid,
				// command address, and the job pid.
				log.Info(logging.DestinationGeneral, "Reattach from a restarted startd; re-announcing",
					"job_pid", jp.pid, "starter_ip_addr", starterAddr)
				sendCtrl(ctx, MsgHello, helloExecuting())
			default:
				log.Debug(logging.DestinationGeneral, "unexpected control message while executing",
					"msg", MsgName(m.typ))
			}
		case ho := <-reconnectCh:
			// CA_RECONNECT_JOB: a reconnecting shadow handed us a fresh syscall
			// socket (the connection it dialed) plus new transfer route material.
			// Swap our remote-syscall client onto it and re-point file transfer, so
			// the rest of the job's syscalls (register_job_info, output transfer,
			// job_exit) go to the reconnecting shadow. The old socket (to the
			// vanished shadow) is dropped.
			old := sysSt
			sysSt = ho.stream
			cli = syscalls.NewClient(sysSt)
			if transfer != nil {
				if ho.transferKey != "" {
					transfer.key = ho.transferKey
				}
				if ho.transferSocket != "" {
					transfer.socket = ho.transferSocket
				}
			}
			if old != nil {
				_ = old.Close()
			}
			log.Info(logging.DestinationGeneral, "reconnected: swapped remote-syscall socket to new shadow",
				"shadow", ho.shadowAddr, "transfer_socket", ho.transferSocket)
			ho.ack <- nil
		case <-ticker.C:
			upd := buildUpdateAd(jp.pid, jp.startTime)
			sendCtrl(ctx, MsgUpdate, upd)
			if err := cli.RegisterJobInfo(ctx, upd); err != nil {
				log.Warn(logging.DestinationGeneral, "register_job_info failed", "err", err.Error())
			}
		case <-waitCh:
			waitDone = true
		}
	}
	end := time.Now()
	jp.closeStdio()
	jp.killGroup() // sweep any stragglers left in the process group

	// (10) Final report: raw waitpid status + JOB_* reason.
	info := inspectWait(jp.cmd.ProcessState)
	reason := syscalls.JobExited
	switch {
	case vacated:
		reason = syscalls.JobKilled
	case info.coreDump:
		reason = syscalls.JobCoredumped
	}
	finalAd := buildFinalAd(info, jp.pid, jp.startTime, end)

	// (11) Output file transfer + job_termination, BEFORE job_exit -- the C++
	// window ("output transfer FIRST, then job_termination(-82), then
	// job_exit"). Skipped when the run was vacated (the job was killed; final
	// transfer is a normal-exit affair -- requeue-time intermediate transfer is
	// a later stage). An output-transfer failure after a successful job is
	// reported with reason JOB_SHOULD_HOLD=112 -- our documented choice: the
	// sandbox results could not be delivered, which the C++ starter surfaces as
	// a hold -- while still sending job_exit so the slot is not wedged.
	if transfer != nil && !vacated {
		if uerr := transfer.uploadOutput(ctx, jobAd); uerr != nil {
			log.Warn(logging.DestinationGeneral, "output file transfer failed", "err", uerr.Error())
			_ = finalAd.Set("TransferOutputFailed", true)
			_ = finalAd.Set("TransferErrorString", uerr.Error())
			reason = syscalls.JobShouldHold
		}
		// job_termination(-82) with the final ad, in the C++ window. The shadow
		// records the ad; a decline is tolerated (only transport loss matters,
		// and job_exit below would surface that).
		if terr := cli.JobTermination(ctx, finalAd); terr != nil {
			log.Warn(logging.DestinationGeneral, "job_termination failed", "err", terr.Error())
		}
	}
	finalize(info.rawStatus, reason, finalAd, true)
	log.Info(logging.DestinationGeneral, "job finished",
		"pid", jp.pid, "status", info.rawStatus, "reason", reason,
		"exit_code", info.exitCode, "signaled", info.signaled)
	return nil
}
