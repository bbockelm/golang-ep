package main

import (
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/golang-htcondor/authz"
	"github.com/bbockelm/golang-htcondor/daemon"

	"github.com/bbockelm/golang-ep/internal/claim"
	"github.com/bbockelm/golang-ep/internal/reconnect"
)

// commandNames names, in denial logs, the commands this socket serves that
// neither cedar's command table nor the DaemonCore defaults do.
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
}

// securityLevels are the authorization levels startd commands are registered
// at, each negotiated with its own SEC_<level>_* policy.
var securityLevels = []string{"ALLOW", "READ", "WRITE", "NEGOTIATOR", "ADMINISTRATOR", "CONFIG", "DAEMON"}

// advertiseLevels are the levels only a DC_NOP_* is registered at here. They
// are negotiated with the DAEMON policy, the level C++ consults for them when
// no SEC_ADVERTISE_<x>_* is set.
var advertiseLevels = []string{"ADVERTISE_STARTD", "ADVERTISE_SCHEDD", "ADVERTISE_MASTER"}

// installAuthz makes srv enforce az on every command it dispatches and
// negotiate each command's security with the SEC_<level>_* policy of the
// level it is registered at, as DaemonCore does. No startd command is
// registered with force_authentication in the C++ startd, so none forces it
// here. base is srv's SecurityConfig; each level's policy is a copy of it
// (sharing its session cache, post-auth policy and credentials) with that
// level's authentication, encryption, integrity and methods. Call it after
// cedarserver.New.
func installAuthz(d *daemon.Daemon, srv *cedarserver.Server, az *daemon.Authz, base *security.SecurityConfig) error {
	srv.Authorizer = az.Authorize
	byLevel := map[string]*security.SecurityConfig{}
	for _, lvl := range securityLevels {
		s, err := d.ServerSecurityConfig(commands.QUERY_STARTD_ADS, lvl)
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
	for _, lvl := range advertiseLevels {
		byLevel[lvl] = byLevel["DAEMON"]
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
// cache, the ALLOW_/DENY_ authorization policy for every command with the
// holes the C++ startd punches (the DaemonCore family, parent and remote
// administration sessions, and the claim sessions it mints), and the DC_*
// defaults. The policy is rebuilt on every reconfig. Call it after
// d.Listener, so the shared-port id is known. The caller registers the
// startd's own commands and serves the result with az.Serve.
func newCommandServer(d *daemon.Daemon, cache *security.SessionCache) (*cedarserver.Server, *daemon.Authz, error) {
	sec, err := d.ServerSecurityConfig(commands.QUERY_STARTD_ADS, "DAEMON")
	if err != nil {
		return nil, nil, err
	}
	sec.SessionCache = cache
	srv := cedarserver.New(sec)
	az, err := d.NewAuthz(daemon.AuthzOptions{
		Holes:        append(authz.DaemonCoreHoles(), authz.StartdMatchSessionHoles()),
		CommandNames: commandNames,
	})
	if err != nil {
		return nil, nil, err
	}
	if err := installAuthz(d, srv, az, sec); err != nil {
		return nil, nil, err
	}
	// DC_NOP* / DC_RECONFIG / DC_OFF so condor_ping, condor_reconfig -daemon,
	// and condor_off -daemon work against our command port.
	d.RegisterDefaultCommands(srv)
	return srv, az, nil
}
