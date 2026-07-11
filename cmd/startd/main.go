// Command startd runs a pure-Go HTCondor condor_startd as a Go daemon under
// condor_master. It boots like any DaemonCore daemon (shared-port endpoint,
// DC_SET_READY / DC_CHILDALIVE, SIGTERM/SIGHUP), answers the standard DC_*
// commands so condor_ping / condor_reconfig / condor_off work, detects the
// host's Cpus/Memory/Disk, carves them into NUM_SLOTS static slots, and
// periodically advertises each slot's public+private machine-ad pair so it
// appears in `condor_status` (the private ad carrying the slot's pre-minted
// secret ClaimId). It serves QUERY_STARTD_ADS, GIVE_STATE, and the Stage-2
// claim surface: REQUEST_CLAIM / RELEASE_CLAIM over claim-id-derived match
// sessions, with an ALIVE lease loop renewing accepted claims against the
// schedd. No job execution yet.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/daemon"
	"github.com/bbockelm/golang-htcondor/logging"

	"github.com/bbockelm/golang-ep/internal/advertise"
	"github.com/bbockelm/golang-ep/internal/claim"
	"github.com/bbockelm/golang-ep/internal/persist"
	"github.com/bbockelm/golang-ep/internal/slot"
	"github.com/bbockelm/golang-ep/internal/startd"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "golang-ep startd:", err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", ":0", "fallback TCP listen address when not inheriting a shared-port endpoint")
	// condor_master appends these standard DaemonCore flags when it launches a
	// daemon; accept them so flag.Parse does not reject our launch.
	localName := flag.String("local-name", "", "HTCondor subsystem local-name; passed by condor_master")
	_ = flag.String("sock", "", "HTCondor shared-port endpoint name; accepted for compatibility (fd inherited via CONDOR_INHERIT)")
	_ = flag.Bool("f", false, "run in the foreground; accepted for compatibility")
	_ = flag.Bool("t", false, "log to the terminal; accepted for compatibility")
	flag.Parse()

	cfg, err := config.NewWithOptions(config.ConfigOptions{Subsystem: "STARTD", LocalName: *localName})
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Bootstrap logging and condor_master integration (drops privileges to the
	// condor user when started as root).
	d, err := daemon.New(daemon.Options{Subsys: "STARTD", Config: cfg})
	if err != nil {
		return err
	}
	log := d.Logger()
	// Route cedar's security/server slog output into StartdLog.
	slog.SetDefault(d.Slog())

	// Server-side security policy from the HTCondor configuration (SEC_* knobs),
	// so this startd authenticates and encrypts exactly like the C++ one.
	sec, err := htcondor.GetServerSecurityConfig(d.Config(), commands.QUERY_STARTD_ADS, "DAEMON")
	if err != nil {
		return fmt.Errorf("building security config: %w", err)
	}

	// A SINGLE session cache shared by (a) the cedar server (inbound resumption:
	// a schedd presenting a claim id resumes the pre-shared match session with no
	// fresh DC_AUTHENTICATE), (b) the claim Minter (which registers each minted
	// session here), and (c) the ALIVE loop (outbound resumption to the schedd).
	sessionCache := security.NewSessionCache()
	sec.SessionCache = sessionCache

	srv := cedarserver.New(sec)
	// DC_NOP / DC_RECONFIG / DC_OFF so condor_ping, condor_reconfig -daemon, and
	// condor_off -daemon work against our command port.
	d.RegisterDefaultCommands(srv)

	// Command-socket listener: the shared-port endpoint inherited from
	// condor_master if present, otherwise a plain TCP bind. Under USE_SHARED_PORT
	// (required) the fallback is not used in practice.
	ln, err := d.Listener(func() (net.Listener, error) {
		return net.Listen("tcp", *listen)
	})
	if err != nil {
		log.Error(logging.DestinationGeneral, "listener setup failed", "err", err.Error())
		return err
	}
	defer func() { _ = ln.Close() }()

	// The startd's externally reachable command sinful ("<host:port?sock=...>"),
	// advertised as StartdIpAddr/MyAddress on every slot ad. Known only after the
	// shared-port listener is adopted.
	sinful := wrapSinful(startdAddr(d, ln))

	// Publish our command address so tools and the collector can find us,
	// exactly like the C++ startd's STARTD_ADDRESS_FILE. The daemon package does
	// NOT do this; main must.
	if path := writeAddressFile(d, cfg, ln); path != "" {
		defer func() { _ = os.Remove(path) }()
	}

	// Resource detection + slot construction (static slots, or a partitionable
	// slot when SLOT_TYPE_1_PARTITIONABLE / EP_PARTITIONABLE_SLOT is set).
	hostname := fullHostname(cfg)
	total := slot.DetectResources(cfg)
	slots := slot.BuildSlots(cfg, hostname, sinful, total, time.Now())
	log.Info(logging.DestinationGeneral, "detected machine resources",
		"cpus", total.Cpus, "memory_mb", total.MemoryMB, "disk_kb", total.DiskKB, "slots", len(slots))

	// core is assigned below; the advertiser and query paths read the LIVE slot
	// set (configured slots + carved dynamic slots) through it.
	var core *startd.Core
	adv := advertise.New(advertise.Options{
		Logger:       log,
		CollectorsFn: func() []string { return resolveCollectors(d.Config()) },
		SlotsFn: func() []*slot.Slot {
			if core != nil {
				return core.LiveSlots()
			}
			return slots
		},
	})

	// Claim-id minting: every slot carries a pre-minted claim id in its private
	// ad (how the negotiator learns the capability). The minted match sessions
	// register into the SAME sessionCache the cedar server resumes from.
	minter := claim.NewMinter(claim.MinterOptions{
		Cache:     sessionCache,
		Sinful:    sinful,
		Birthdate: time.Now().Unix(),
	})

	// Durable claim store (Stage 6 write side of restart survival): one record
	// per slot, committed at every transition, under EP_CLAIMS_DIR (default
	// $(SPOOL)/ep/claims). Best-effort -- a store failure logs but does not stop
	// the startd (it just forfeits Stage-7 re-adoption for this run).
	var store *persist.Store
	if dir := claimsDir(cfg); dir != "" {
		if s, err := persist.Open(dir); err != nil {
			log.Warn(logging.DestinationGeneral, "opening claim store failed; persistence disabled",
				"dir", dir, "err", err.Error())
		} else {
			store = s
			defer func() { _ = store.Close() }()
			log.Info(logging.DestinationGeneral, "claim store open", "dir", dir)
		}
	}

	core = startd.New(startd.Options{
		Logger:         log,
		Slots:          slots,
		Advertiser:     adv,
		UpdateInterval: configSeconds(cfg, "UPDATE_INTERVAL", 300*time.Second),
		Minter:         minter,
		SessionCache:   sessionCache,
		AlivesMissed:   configInt(cfg, "MAX_CLAIM_ALIVES_MISSED", claim.DefaultAlivesMissed),
		MatchTimeout:   configSeconds(cfg, "MATCH_TIMEOUT", 120*time.Second),
		// Stage 3: ACTIVATE_CLAIM + goroutine starters.
		ExecuteDir:            slot.ExecuteDir(cfg),
		StarterUpdateInterval: configSeconds(cfg, "STARTER_UPDATE_INTERVAL", 300*time.Second),
		UIDDomain:             configString(cfg, "UID_DOMAIN", hostname),
		FileSystemDomain:      configString(cfg, "FILESYSTEM_DOMAIN", hostname),
		// Stage 6: process-mode starters + persistence.
		StarterMode:      configString(cfg, "STARTER_MODE", "goroutine"),
		StarterPath:      configString(cfg, "STARTER", ""),
		StarterSocketDir: starterSocketDir(cfg),
		KillingTimeout:   configSeconds(cfg, "KILLING_TIMEOUT", 30*time.Second),
		Store:            store,
	})
	core.RegisterCommands(srv)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the event loop (advertises on startup and every UPDATE_INTERVAL);
	// Stop cancels it and invalidates the slot ads best-effort.
	core.Start(ctx)
	defer core.Stop()

	// Stage 7 restart survival: re-adopt any claims persisted by a prior instance
	// of this startd -- re-register their match sessions, rebuild the claimed
	// slots, and redial the (surviving, process-mode) starters that kept their
	// jobs running across the restart. A no-op on a fresh SPOOL.
	core.Adopt()

	log.Info(logging.DestinationGeneral, "golang-ep startd starting",
		"listen", ln.Addr().String(), "under_master", d.UnderMaster(), "sinful", sinful)

	return d.Serve(ctx, ln, srv.Serve)
}

// fullHostname derives the machine name advertised in the slot ads.
func fullHostname(cfg *config.Config) string {
	if v, ok := cfg.Get("FULL_HOSTNAME"); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return "localhost"
}

// startdAddr is this startd's externally reachable command address: the
// shared-port sinful when under condor_master, otherwise the listen address.
func startdAddr(d *daemon.Daemon, ln net.Listener) string {
	if sinful, ok := d.AdvertisedSinful(); ok {
		return sinful
	}
	return ln.Addr().String()
}

// writeAddressFile publishes the startd's command address to STARTD_ADDRESS_FILE
// (default $(LOG)/.startd_address) as a sinful string, exactly like the C++
// startd. Returns the path written (for cleanup), or "" if none.
func writeAddressFile(d *daemon.Daemon, cfg *config.Config, ln net.Listener) string {
	path, ok := cfg.Get("STARTD_ADDRESS_FILE")
	if !ok || strings.TrimSpace(path) == "" {
		logDir, ok := cfg.Get("LOG")
		if !ok || logDir == "" {
			return ""
		}
		path = filepath.Join(logDir, ".startd_address")
	}
	if err := os.WriteFile(path, []byte("<"+startdAddr(d, ln)+">\n"), 0o644); err != nil {
		slog.Warn("could not write startd address file", "path", path, "err", err)
		return ""
	}
	return path
}

// resolveCollectors returns the collector endpoints to advertise to, derived
// from COLLECTOR_HOST (falling back to COLLECTOR_ADDRESS_FILE when the host has
// no usable port, e.g. a co-located collector behind shared port). Mirrors
// golang-ap's schedd.
func resolveCollectors(cfg *config.Config) []string {
	raw, _ := cfg.Get("COLLECTOR_HOST")
	var out []string
	for _, e := range splitHostList(raw) {
		if hasUsablePort(e) {
			out = append(out, e)
		} else if addr := readCollectorAddressFile(cfg); addr != "" {
			out = append(out, addr)
		}
	}
	if len(out) == 0 {
		if addr := readCollectorAddressFile(cfg); addr != "" {
			out = append(out, addr)
		}
	}
	return out
}

func splitHostList(raw string) []string {
	var out []string
	for _, h := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	}) {
		if h != "" {
			out = append(out, h)
		}
	}
	return out
}

func hasUsablePort(entry string) bool {
	s := strings.TrimSpace(entry)
	s = strings.TrimPrefix(strings.TrimSuffix(s, ">"), "<")
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	_, port, err := net.SplitHostPort(s)
	return err == nil && port != "" && port != "0"
}

func readCollectorAddressFile(cfg *config.Config) string {
	path, ok := cfg.Get("COLLECTOR_ADDRESS_FILE")
	if !ok || path == "" {
		logDir, ok := cfg.Get("LOG")
		if !ok || logDir == "" {
			return ""
		}
		path = filepath.Join(logDir, ".collector_address")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			return line
		}
	}
	return ""
}

// claimsDir returns the durable claim-store directory: EP_CLAIMS_DIR if set,
// else $(SPOOL)/ep/claims, else "" (persistence disabled when no SPOOL).
func claimsDir(cfg *config.Config) string {
	if v := configString(cfg, "EP_CLAIMS_DIR", ""); v != "" {
		return v
	}
	if spool := configString(cfg, "SPOOL", ""); spool != "" {
		return filepath.Join(spool, "ep", "claims")
	}
	return ""
}

// starterSocketDir returns the directory per-claim starter control sockets live
// under: EP_STARTER_SOCKET_DIR if set, else $(SPOOL)/ep/starters. Kept short for
// the macOS sun_path limit; empty (no SPOOL) rejects process-mode activation.
func starterSocketDir(cfg *config.Config) string {
	if v := configString(cfg, "EP_STARTER_SOCKET_DIR", ""); v != "" {
		return v
	}
	if spool := configString(cfg, "SPOOL", ""); spool != "" {
		return filepath.Join(spool, "ep", "starters")
	}
	return ""
}

func configSeconds(cfg *config.Config, key string, def time.Duration) time.Duration {
	if v, ok := cfg.Get(key); ok {
		if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return def
}

func configString(cfg *config.Config, key, def string) string {
	if v, ok := cfg.Get(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func configInt(cfg *config.Config, key string, def int) int {
	if v, ok := cfg.Get(key); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// wrapSinful ensures a command address is a canonical HTCondor sinful string
// wrapped in angle brackets.
func wrapSinful(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if strings.HasPrefix(addr, "<") {
		return addr
	}
	return "<" + addr + ">"
}
