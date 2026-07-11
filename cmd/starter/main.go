// Command starter is the EP's process-mode condor_starter equivalent: a thin
// wrapper over internal/starter that the startd spawns (STARTER_MODE=process),
// connected back to the startd over a per-claim Unix domain socket. It is NOT a
// DaemonCore daemon -- no shared port, no collector, no command port: it binds
// the control socket the startd told it to, receives the ACTIVATE syscall
// connection via SCM_RIGHTS, runs the job, and reports lifecycle over the
// control channel. On exit it drops a `.exit` marker (waitpid status, JOB_*
// reason, final ad) into the sandbox, which Stage-7 restart recovery consumes to
// learn the outcome of a job whose starter finished while the startd was down.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/golang-htcondor/logging"

	"github.com/bbockelm/golang-ep/internal/starter"
)

// exitMarker is the JSON the starter writes to <sandbox>/.exit on the way out.
type exitMarker struct {
	WaitpidStatus int    `json:"waitpid_status"`
	Reason        int    `json:"reason"` // JOB_* code (exit.h), e.g. 100=JOB_EXITED
	FinalAd       string `json:"final_ad,omitempty"`
	ExitTime      int64  `json:"exit_time"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "golang-ep starter:", err)
		os.Exit(1)
	}
}

func run() error {
	socket := flag.String("socket", "", "startd<->starter control Unix socket path (required)")
	slotName := flag.String("slot", "", "claimed slot name")
	claimID := flag.String("claim", "", "public (secret-elided) claim id")
	sandbox := flag.String("sandbox", "", "job sandbox directory (required; .exit marker lands here)")
	logPath := flag.String("log", "", "starter log destination (file path; empty = stderr)")
	updateSecs := flag.Int("update-interval", 0, "periodic register_job_info cadence, seconds (0 = default)")
	uidDomain := flag.String("uid-domain", "", "UidDomain for register_starter_info")
	fsDomain := flag.String("fs-domain", "", "FileSystemDomain for register_starter_info")
	acceptSecs := flag.Int("accept-timeout", 30, "seconds to wait for the startd to dial the control socket")
	gapLeaseSecs := flag.Int("startd-gap-lease", 1200, "seconds a control-channel gap (startd down) is tolerated before self-destruct")
	cmdBind := flag.String("command-bind", "127.0.0.1:0", "TCP bind address for the starter's CA command port (StarterIpAddr)")
	flag.Parse()

	if *socket == "" {
		return fmt.Errorf("-socket is required")
	}
	if *sandbox == "" {
		return fmt.Errorf("-sandbox is required")
	}

	// Log at Info by default (the package default is Warn, which would suppress
	// the lifecycle lines -- including our pid -- that make a process starter
	// observable). A file path routes to a StarterLog; empty goes to stderr.
	logCfg := &logging.Config{DefaultLevel: logging.VerbosityInfo}
	if *logPath != "" {
		logCfg.OutputPath = *logPath
	}
	log, err := logging.New(logCfg)
	if err != nil {
		return fmt.Errorf("building logger: %w", err)
	}
	log.Info(logging.DestinationGeneral, "process starter starting",
		"socket", *socket, "slot", *slotName, "sandbox", *sandbox, "pid", os.Getpid())

	// Bind + accept the startd's control connection before Run. ListenStarter
	// blocks until the startd dials (bounded by accept-timeout), then runs a
	// DURABLE relay that survives startd restarts by re-accepting redials on the
	// same socket for up to the startd-gap lease.
	side, err := starter.ListenStarter(*socket,
		time.Duration(*acceptSecs)*time.Second,
		time.Duration(*gapLeaseSecs)*time.Second, log)
	if err != nil {
		return fmt.Errorf("establishing control channel: %w", err)
	}

	// SIGTERM/SIGINT -> cancel the run (hard vacate; the startd normally drives
	// vacate over the control channel, but honor signals too).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		select {
		case s := <-sigCh:
			log.Warn(logging.DestinationGeneral, "starter received signal; vacating", "signal", s.String())
			cancel()
		case <-ctx.Done():
		}
	}()

	// Capture the terminal outcome for the .exit marker (OnFinal fires once).
	var (
		markerMu sync.Mutex
		marker   *exitMarker
	)
	opts := starter.Options{
		Logger:              log,
		SlotName:            *slotName,
		ClaimID:             *claimID,
		UpdateInterval:      time.Duration(*updateSecs) * time.Second,
		UIDDomain:           *uidDomain,
		FileSystemDomain:    *fsDomain,
		EnableCommandServer: true,
		CommandBindAddr:     *cmdBind,
		OnFinal: func(status, reason int, finalAd *classad.ClassAd) {
			m := &exitMarker{WaitpidStatus: status, Reason: reason, ExitTime: time.Now().Unix()}
			if finalAd != nil {
				m.FinalAd = finalAd.String()
			}
			markerMu.Lock()
			marker = m
			markerMu.Unlock()
		},
	}

	runErr := starter.Run(ctx, side, opts)

	// Always drop a .exit marker so a startd that redials a gone starter (Stage
	// 7) can read the outcome. If the run aborted before any job outcome, record
	// JOB_NOT_STARTED so the reader still sees a terminal state.
	markerMu.Lock()
	m := marker
	markerMu.Unlock()
	if m == nil {
		m = &exitMarker{Reason: 108 /* JOB_NOT_STARTED */, ExitTime: time.Now().Unix()}
	}
	if werr := writeExitMarker(*sandbox, m); werr != nil {
		log.Warn(logging.DestinationGeneral, "writing .exit marker failed", "err", werr.Error())
	}

	if runErr != nil {
		log.Warn(logging.DestinationGeneral, "starter run ended with error", "err", runErr.Error())
		return runErr
	}
	log.Info(logging.DestinationGeneral, "process starter exiting cleanly",
		"status", m.WaitpidStatus, "reason", m.Reason)
	return nil
}

// writeExitMarker atomically writes the .exit marker into the sandbox.
func writeExitMarker(sandbox string, m *exitMarker) error {
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshaling marker: %w", err)
	}
	path := filepath.Join(sandbox, ".exit")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
