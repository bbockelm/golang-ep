package main

import (
	"context"
	"log/slog"
	"net"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/authz"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/daemon"
	"github.com/bbockelm/golang-htcondor/logging"

	"github.com/bbockelm/golang-ep/internal/claim"
	"github.com/bbockelm/golang-ep/internal/reconnect"
)

// startdAuthz is the ALLOW_<level>/DENY_<level> authorization policy for
// every command served on the startd's command socket: the claim protocol,
// the query commands, CA_CMD and the DC_* defaults. It is built once from
// the configuration and rebuilt on reconfig, as the C++ daemons rebuild
// IpVerify.
type startdAuthz struct {
	cur atomic.Pointer[authzState]
}

type authzState struct {
	policy *authz.Policy
	cfg    authz.ConfigGetter
	holes  map[string][]authz.Perm
}

// authzSubsys is the subsystem whose ALLOW_<level>_<subsys> variants apply.
const authzSubsys = "STARTD"

// familyHoles are the levels C++ DaemonCore grants the identities of the
// sessions condor_master shares with its children whatever ALLOW_/DENY_ say
// (IpVerify::PunchHole in daemon_core.cpp, for the family session and the
// inherited parent session), with the levels each one implies. cedar
// attributes these identities only to a peer resuming the inherited session.
var familyHoles = map[string][]authz.Perm{
	"condor@family": {
		authz.PermAdministrator, authz.PermDaemon, authz.PermNegotiator,
		authz.PermAdvertiseMaster, authz.PermAdvertiseSchedd, authz.PermAdvertiseStartd,
		authz.PermWrite, authz.PermRead,
	},
	"condor@parent": {authz.PermAdministrator, authz.PermDaemon, authz.PermWrite, authz.PermRead},
}

// matchSessionHole is what the C++ startd grants the identity of the claim
// sessions it mints (submit-side@matchsession) while
// SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION is on: DAEMON, and the WRITE and
// READ it implies (startd_main.cpp init_params). The schedd and its shadows
// send REQUEST_CLAIM, ACTIVATE_CLAIM, RELEASE_CLAIM, DEACTIVATE_CLAIM* and
// CA_CMD over those sessions.
var matchSessionHole = []authz.Perm{authz.PermDaemon, authz.PermWrite, authz.PermRead}

func newStartdAuthz(cfg authz.ConfigGetter) (*startdAuthz, error) {
	a := &startdAuthz{}
	if err := a.reload(cfg); err != nil {
		return nil, err
	}
	return a, nil
}

// reload rebuilds the policy, and the claim-session hole, from cfg; commands
// dispatched afterwards are checked against the new one.
func (a *startdAuthz) reload(cfg authz.ConfigGetter) error {
	p, err := authz.NewPolicy(cfg, authzSubsys)
	if err != nil {
		return err
	}
	holes := make(map[string][]authz.Perm, len(familyHoles)+1)
	for id, perms := range familyHoles {
		holes[id] = perms
	}
	if configBool(cfg, "SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION", true) {
		holes[security.SubmitSideMatchSessionFQU] = matchSessionHole
	}
	a.cur.Store(&authzState{policy: p, cfg: cfg, holes: holes})
	return nil
}

// Authorize reports whether user, connecting from peerAddr, holds the
// authorization level perm. It has the signature of cedar's
// Server.Authorizer.
func (a *startdAuthz) Authorize(perm, peerAddr, user string) bool {
	st := a.cur.Load()
	for _, p := range st.holes[user] {
		if string(p) == perm {
			return true
		}
	}
	return st.policy.Authorize(perm, peerAddr, user)
}

// policyKnob returns the setting that supplies prefix+perm (prefix "ALLOW_"
// or "DENY_"), or "" if none is set. An unset level falls back to DEFAULT,
// and at each level the _STARTD variant is consulted first, as in
// authz.Policy.
func (a *startdAuthz) policyKnob(prefix, perm string) string {
	cfg := a.cur.Load().cfg
	for _, p := range []string{perm, string(authz.PermDefault)} {
		for _, k := range []string{prefix + p + "_" + authzSubsys, prefix + p} {
			if _, ok := cfg.Get(k); ok {
				return k
			}
		}
	}
	return ""
}

// refusedRE matches the error cedar's Server.ServeConn returns when the
// Authorizer refuses a command: it names the command and the identity. The
// denial tests in authz_test.go fail if cedar changes that wording.
var refusedRE = regexp.MustCompile(`command (\d+) \([^)]*\) refused: identity ("(?:[^"\\]|\\.)*") is not authorized`)

// logDenial logs err if it is a command the authorization policy refused,
// with the command, its authorization level, the peer, the identity, and
// the ALLOW_/DENY_ settings that decide that level.
func (a *startdAuthz) logDenial(log *slog.Logger, srv *cedarserver.Server, peerAddr string, err error) {
	m := refusedRE.FindStringSubmatch(err.Error())
	if m == nil {
		return
	}
	cmd, convErr := strconv.Atoi(m[1])
	if convErr != nil {
		return
	}
	user, convErr := strconv.Unquote(m[2])
	if convErr != nil {
		return
	}
	perms := srv.CommandPerms(cmd)
	var allow, deny []string
	for _, perm := range perms {
		k := a.policyKnob("ALLOW_", perm)
		if k == "" {
			k = "ALLOW_" + perm + " (unset)"
		}
		allow = append(allow, k)
		if k := a.policyKnob("DENY_", perm); k != "" {
			deny = append(deny, k)
		}
	}
	log.Warn("PERMISSION DENIED",
		"command", commandName(cmd),
		"command_id", cmd,
		"level", strings.Join(perms, ","),
		"peer", peerAddr,
		"user", user,
		"allow_knob", strings.Join(allow, ","),
		"deny_knob", strings.Join(deny, ","),
		"destination", "security")
}

// commandNames names the commands this socket serves that cedar's command
// table does not.
var commandNames = map[int]string{
	claim.CmdRequestClaim:            "REQUEST_CLAIM",
	claim.CmdReleaseClaim:            "RELEASE_CLAIM",
	claim.CmdActivateClaim:           "ACTIVATE_CLAIM",
	claim.CmdDeactivateClaim:         "DEACTIVATE_CLAIM",
	claim.CmdDeactivateClaimForcibly: "DEACTIVATE_CLAIM_FORCIBLY",
	claim.CmdDeactivateClaimJobDone:  "DEACTIVATE_CLAIM_JOB_DONE",
	claim.CmdDeactivateFinalXfer:     "DEACTIVATE_CLAIM_FINAL_XFER",
	claim.CmdMatchInfo:               "MATCH_INFO",
	commands.GIVE_STATE:              "GIVE_STATE",
	reconnect.CACmd:                  "CA_CMD",
	commands.DC_RECONFIG:             "DC_RECONFIG",
	commands.DC_RECONFIG_FULL:        "DC_RECONFIG_FULL",
	commands.DC_OFF_GRACEFUL:         "DC_OFF_GRACEFUL",
	commands.DC_OFF_PEACEFUL:         "DC_OFF_PEACEFUL",
	commands.DC_OFF_FAST:             "DC_OFF_FAST",
	commands.DC_NOP:                  "DC_NOP",
	commands.DC_NOP_READ:             "DC_NOP_READ",
	commands.DC_NOP_WRITE:            "DC_NOP_WRITE",
	commands.DC_NOP_NEGOTIATOR:       "DC_NOP_NEGOTIATOR",
}

// commandName returns cmd's HTCondor name, or its number if it has none.
func commandName(cmd int) string {
	if n := commands.GetCommandName(cmd); n != "" {
		return n
	}
	if n, ok := commandNames[cmd]; ok {
		return n
	}
	return strconv.Itoa(cmd)
}

// serveCommands returns a serve loop for srv: like cedar's Server.Serve, it
// accepts connections on a listener and serves each on srv until ctx is
// cancelled, and it also logs every command the authorization policy refused.
// cedar closes a refused connection without logging it, so this is the
// operator's record of a denial.
func serveCommands(srv *cedarserver.Server, az *startdAuthz, log *slog.Logger) func(context.Context, net.Listener) error {
	return func(ctx context.Context, ln net.Listener) error {
		go func() {
			<-ctx.Done()
			_ = ln.Close()
		}()
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return err
			}
			_ = srv.KeepAlive.Apply(conn)
			go func() {
				peer := conn.RemoteAddr().String()
				defer func() {
					if r := recover(); r != nil {
						log.Error("panic in connection handler; recovered",
							"panic", r, "remote", peer, "stack", string(debug.Stack()))
						_ = conn.Close()
					}
				}()
				if err := srv.ServeConn(ctx, conn); err != nil {
					az.logDenial(log, srv, peer, err)
				}
			}()
		}
	}
}

// securityLevels are the authorization levels startd commands are registered
// at, each negotiated with its own SEC_<level>_* policy.
var securityLevels = []string{"ALLOW", "READ", "WRITE", "NEGOTIATOR", "ADMINISTRATOR", "DAEMON"}

// installAuthz makes srv enforce az on every command it dispatches and
// negotiate each command's security with the SEC_<level>_* policy of the
// level it is registered at, as DaemonCore does. No startd command is
// registered with force_authentication in the C++ startd, so none forces it
// here. base is srv's SecurityConfig; each level's policy is a copy of it
// (sharing its session cache, post-auth policy and credentials) with that
// level's authentication, encryption, integrity and methods. Call it after
// cedarserver.New.
func installAuthz(srv *cedarserver.Server, az *startdAuthz, cfg *config.Config, base *security.SecurityConfig) error {
	srv.Authorizer = az.Authorize
	// With an Authorizer, cedar's post-auth reply lists every command the
	// peer is authorized for, so a C++ client resumes the session for its
	// next command. That reply lacks TriedAuthentication, so a resuming C++
	// client that then forces authentication re-authenticates mid-command,
	// which cedar does not serve. Keep advertising only the negotiated
	// command, as without an Authorizer; every command is still authorized
	// when it is dispatched.
	if post := base.PostAuthPolicy; post != nil {
		base.PostAuthPolicy = func(authUser, peerAddr string, authenticated, encrypted bool) (string, []int) {
			fqu, _ := post(authUser, peerAddr, authenticated, encrypted)
			return fqu, nil
		}
	}
	byLevel := map[string]*security.SecurityConfig{}
	for _, lvl := range securityLevels {
		s, err := htcondor.GetServerSecurityConfig(cfg, commands.QUERY_STARTD_ADS, lvl)
		if err != nil {
			return err
		}
		c := *base
		c.Authentication = s.Authentication
		c.Encryption = s.Encryption
		c.Integrity = s.Integrity
		c.AuthMethods = s.AuthMethods
		c.CryptoMethods = s.CryptoMethods
		byLevel[lvl] = &c
	}
	srv.SecurityConfigForCommand = func(command int) *security.SecurityConfig {
		perms := srv.CommandPerms(command)
		if len(perms) == 0 {
			return nil
		}
		return byLevel[perms[0]]
	}
	return nil
}

// newCommandServer builds the startd's command server: the SEC_* security
// policy (each command negotiated at its own level), sessions resumed from
// cache, the ALLOW_/DENY_ authorization policy for every command, and the
// DC_* defaults. The policy is rebuilt on every reconfig. Call it after
// d.Listener, so the shared-port id is known. The caller registers the
// startd's own commands and serves the result with serveCommands.
func newCommandServer(d *daemon.Daemon, cache *security.SessionCache) (*cedarserver.Server, *startdAuthz, error) {
	cfg := d.Config()
	sec, err := htcondor.GetServerSecurityConfig(cfg, commands.QUERY_STARTD_ADS, "DAEMON")
	if err != nil {
		return nil, nil, err
	}
	sec.SessionCache = cache
	// Peer identities are user@domain; a peer that authenticates without a
	// domain of its own (FS, CLAIMTOBE) is in UID_DOMAIN. Behind shared port,
	// FS channel binding checks a client-reported sock id against ours. Set on
	// the base config, so every level's copy carries them.
	if uid, ok := cfg.Get("UID_DOMAIN"); ok {
		sec.UIDDomain = strings.TrimSpace(uid)
	}
	sec.SharedPortID = d.SharedPortName()
	srv := cedarserver.New(sec)
	az, err := newStartdAuthz(cfg)
	if err != nil {
		return nil, nil, err
	}
	if err := installAuthz(srv, az, cfg, sec); err != nil {
		return nil, nil, err
	}
	// DC_NOP / DC_RECONFIG / DC_OFF so condor_ping, condor_reconfig -daemon, and
	// condor_off -daemon work against our command port.
	d.RegisterDefaultCommands(srv)
	log := d.Logger()
	d.OnReconfig(func(newCfg *config.Config) {
		if err := az.reload(newCfg); err != nil {
			log.Error(logging.DestinationSecurity, "reloading authorization policy failed; keeping the previous one", "err", err.Error())
		}
	})
	return srv, az, nil
}

// configBool reads a boolean knob the way HTCondor's param_boolean does,
// returning def when it is unset or not a boolean.
func configBool(cfg authz.ConfigGetter, key string, def bool) bool {
	v, ok := cfg.Get(key)
	if !ok {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "t", "yes", "y", "1":
		return true
	case "false", "f", "no", "n", "0":
		return false
	}
	return def
}
