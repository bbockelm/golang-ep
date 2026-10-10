package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/daemon"
	"github.com/bbockelm/golang-htcondor/logging"
	hstartd "github.com/bbockelm/golang-htcondor/startd"

	"github.com/bbockelm/golang-ep/internal/claim"
	"github.com/bbockelm/golang-ep/internal/reconnect"
	"github.com/bbockelm/golang-ep/internal/slot"
	"github.com/bbockelm/golang-ep/internal/startd"
)

// These tests drive the startd's command server as run() builds it
// (newCommandServer, the startd's command registrations, serveCommands under
// daemon.Serve) over loopback, and check that the ALLOW_/DENY_ policy decides
// which identities may run which command.
//
// Identities are HTCondor's full user@domain names. A peer is given one by a
// pre-shared session the startd attributes to that identity (the way a claim
// or family session carries its identity), so the policy sees exactly the
// name under test whatever an authentication method reports.

const testTrustDomain = "pool"

// authzStartd is a running startd command server plus the means to reach it
// as any identity.
type authzStartd struct {
	t         *testing.T
	addr      string
	cfgFile   string
	keyDir    string
	cache     *security.SessionCache
	srv       *cedarserver.Server
	az        *startdAuthz
	core      *startd.Core
	reconfigs atomic.Int32
	served    chan struct{} // closed when daemon.Serve returns
	serveErr  error
	records   chan slog.Record
}

// startAuthzStartd serves the startd's commands with the ALLOW_/DENY_ policy
// knobs, from a configuration file reloaded on reconfig.
// SEC_DEFAULT_AUTHENTICATION is OPTIONAL, so an anonymous peer can negotiate
// every level and only the authorization policy keeps it out.
func startAuthzStartd(t *testing.T, knobs map[string]string) *authzStartd {
	t.Helper()
	as := &authzStartd{
		t:       t,
		cfgFile: filepath.Join(t.TempDir(), "condor_config"),
		keyDir:  t.TempDir(),
		served:  make(chan struct{}),
		records: make(chan slog.Record, 64),
	}
	if err := security.GeneratePoolSigningKey(filepath.Join(as.keyDir, "POOL")); err != nil {
		t.Fatal(err)
	}
	as.writeConfig(knobs)
	t.Setenv("CONDOR_CONFIG", as.cfgFile)

	// As run() builds it.
	cfg, err := config.NewWithOptions(config.ConfigOptions{Subsystem: "STARTD"})
	if err != nil {
		t.Fatal(err)
	}
	log, err := logging.New(&logging.Config{OutputPath: filepath.Join(t.TempDir(), "log")})
	if err != nil {
		t.Fatal(err)
	}
	d, err := daemon.New(daemon.Options{Subsys: "STARTD", Config: cfg, Logger: log, ShutdownGrace: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	as.cache = security.NewSessionCache()
	srv, az, err := newCommandServer(d, as.cache)
	if err != nil {
		t.Fatal(err)
	}
	as.srv, as.az = srv, az
	// Runs after the policy reload newCommandServer registered.
	d.OnReconfig(func(*config.Config) { as.reconfigs.Add(1) })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	as.addr = ln.Addr().String()
	as.core = newCore(t, log, as.cache, "<"+as.addr+">")
	as.core.RegisterCommands(srv)

	ctx, cancel := context.WithCancel(context.Background())
	as.core.Start(ctx)
	logger := slog.New(&recordHandler{ch: as.records})
	go func() {
		defer close(as.served)
		as.serveErr = d.Serve(ctx, ln, serveCommands(srv, az, logger))
	}()
	t.Cleanup(func() {
		cancel()
		<-as.served
		as.core.Stop()
	})
	return as
}

// writeConfig (re)writes the startd's configuration file with knobs.
func (as *authzStartd) writeConfig(knobs map[string]string) {
	as.t.Helper()
	var b strings.Builder
	for _, kv := range [][2]string{
		{"LOCAL_CONFIG_FILE", ""},
		{"LOCAL_CONFIG_DIR", ""},
		{"SEC_DEFAULT_AUTHENTICATION", "OPTIONAL"},
		{"SEC_DEFAULT_ENCRYPTION", "OPTIONAL"},
		{"SEC_DEFAULT_INTEGRITY", "OPTIONAL"},
		{"SEC_DEFAULT_AUTHENTICATION_METHODS", "IDTOKENS"},
		{"SEC_DEFAULT_CRYPTO_METHODS", "AES"},
		{"SEC_TOKEN_POOL_SIGNING_KEY_FILE", filepath.Join(as.keyDir, "POOL")},
		{"SEC_PASSWORD_DIRECTORY", as.keyDir},
		{"TRUST_DOMAIN", testTrustDomain},
	} {
		fmt.Fprintf(&b, "%s = %s\n", kv[0], kv[1])
	}
	for k, v := range knobs {
		fmt.Fprintf(&b, "%s = %s\n", k, v)
	}
	if err := os.WriteFile(as.cfgFile, []byte(b.String()), 0o644); err != nil {
		as.t.Fatal(err)
	}
}

// newCore builds a startd core with two static slots whose claim sessions
// are minted into cache, as run() does.
func newCore(t *testing.T, log *logging.Logger, cache *security.SessionCache, sinful string) *startd.Core {
	t.Helper()
	cfg, err := config.NewFromReader(strings.NewReader("NUM_SLOTS=2\nSTART=TRUE\n"))
	if err != nil {
		t.Fatal(err)
	}
	total := slot.Resources{Cpus: 4, MemoryMB: 2048, DiskKB: 200000}
	return startd.New(startd.Options{
		Logger:       log,
		Slots:        slot.BuildStaticSlots(cfg, "testhost", sinful, total, time.Now()),
		Minter:       claim.NewMinter(claim.MinterOptions{Cache: cache, Sinful: sinful, Birthdate: time.Now().Unix()}),
		SessionCache: cache,
		AlivesMissed: claim.DefaultAlivesMissed,
		ExecuteDir:   t.TempDir(),
		UIDDomain:    testTrustDomain,
	})
}

// as returns a client security config for a peer the startd knows as
// identity: a session pre-shared with the startd and attributed to identity
// there. "" returns an anonymous config. Each config carries its own session
// cache, so no session (and so no identity) is reused across clients.
func (as *authzStartd) as(identity string) *security.SecurityConfig {
	as.t.Helper()
	if identity == "" {
		return &security.SecurityConfig{
			AuthMethods:    []security.AuthMethod{},
			Authentication: security.SecurityNever,
			Encryption:     security.SecurityNever,
			Integrity:      security.SecurityNever,
			SessionCache:   security.NewSessionCache(),
		}
	}
	minted, err := security.MintClaimSession(as.cache, security.MintClaimOptions{
		Sinful:  "<127.0.0.1:1>",
		PeerFQU: identity,
	})
	if err != nil {
		as.t.Fatal(err)
	}
	cc := security.NewSessionCache()
	sid, err := security.ImportClaimSession(cc, minted.ClaimID(), security.ClaimSessionOptions{PeerFQU: "startd@" + testTrustDomain})
	if err != nil {
		as.t.Fatal(err)
	}
	return &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthToken},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		SessionID:      sid,
		SessionCache:   cc,
	}
}

// token returns a client security config that authenticates with an IDTOKEN
// for subject, signed by the startd's pool key.
func (as *authzStartd) token(subject string) *security.SecurityConfig {
	as.t.Helper()
	now := time.Now().Unix()
	tok, err := security.GenerateJWT(as.keyDir, "POOL", subject, testTrustDomain, now, now+3600, nil)
	if err != nil {
		as.t.Fatal(err)
	}
	return &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthToken},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		Token:          tok,
		TrustDomain:    testTrustDomain,
		SessionCache:   security.NewSessionCache(),
	}
}

// dial connects as sec's identity to run cmd.
func (as *authzStartd) dial(sec *security.SecurityConfig, cmd int) (*client.HTCondorClient, context.Context, error) {
	as.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	as.t.Cleanup(cancel)
	cs := *sec
	cs.Command = cmd
	cl, err := client.ConnectAndAuthenticate(ctx, as.addr, &cs)
	if err != nil {
		return nil, ctx, err
	}
	as.t.Cleanup(func() { _ = cl.Close() })
	return cl, ctx, nil
}

// send runs a DC_* command that takes no payload and has no reply, as
// condor_reconfig and condor_off send it, and returns once the startd has
// closed the connection: by then the handler, if it ran, has finished.
func (as *authzStartd) send(sec *security.SecurityConfig, cmd int) {
	as.t.Helper()
	cl, ctx, err := as.dial(sec, cmd)
	if err != nil {
		as.t.Fatalf("connecting for %s: %v", commandName(cmd), err)
	}
	if err := message.NewMessageForStream(cl.GetStream()).FinishMessage(ctx); err != nil {
		as.t.Fatalf("sending %s: %v", commandName(cmd), err)
	}
	if _, err := message.NewMessageFromStream(cl.GetStream()).GetInt(ctx); err == nil {
		as.t.Fatalf("%s: unexpected reply", commandName(cmd))
	}
}

// queryAds runs QUERY_STARTD_ADS as sec's identity and returns the slot ads,
// or an error if the startd refused the command.
func (as *authzStartd) queryAds(sec *security.SecurityConfig) ([]*classad.ClassAd, error) {
	as.t.Helper()
	cl, ctx, err := as.dial(sec, commands.QUERY_STARTD_ADS)
	if err != nil {
		return nil, err
	}
	m := message.NewMessageForStream(cl.GetStream())
	if err := m.PutClassAd(ctx, mustParse(as.t, `[Requirements=true]`)); err != nil {
		return nil, err
	}
	if err := m.FinishMessage(ctx); err != nil {
		return nil, err
	}
	in := message.NewMessageFromStream(cl.GetStream())
	var out []*classad.ClassAd
	for {
		more, err := in.GetInt(ctx)
		if err != nil {
			return nil, err
		}
		if more == 0 {
			return out, nil
		}
		ad, err := in.GetClassAd(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, ad)
	}
}

// requestClaim sends REQUEST_CLAIM for an unknown claim id as sec's identity
// and returns the startd's reply code (the claim is refused, so NOT_OK), or
// an error if the startd refused the command.
func (as *authzStartd) requestClaim(sec *security.SecurityConfig) (int, error) {
	as.t.Helper()
	cl, ctx, err := as.dial(sec, claim.CmdRequestClaim)
	if err != nil {
		return 0, err
	}
	m := message.NewMessageForStream(cl.GetStream())
	if err := m.PutString(ctx, "<127.0.0.1:1>#1#1#[]unknown"); err != nil {
		return 0, err
	}
	if err := m.PutClassAd(ctx, mustParse(as.t, `[RequestCpus=1]`)); err != nil {
		return 0, err
	}
	if err := m.PutString(ctx, "<127.0.0.1:1>"); err != nil {
		return 0, err
	}
	if err := m.PutInt(ctx, 300); err != nil {
		return 0, err
	}
	if err := m.PutInt(ctx, 0); err != nil {
		return 0, err
	}
	if err := m.FinishMessage(ctx); err != nil {
		return 0, err
	}
	return message.NewMessageFromStream(cl.GetStream()).GetInt(ctx)
}

// claimSlot claims the first slot over its own claim session, as a schedd
// does, and reports whether the startd granted it.
func (as *authzStartd) claimSlot() (bool, error) {
	as.t.Helper()
	sc, err := hstartd.New(as.core.Slots()[0].Claim().ClaimID(), nil)
	if err != nil {
		as.t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ad := mustParse(as.t, `[RequestCpus=1; RequestMemory=1; RequestDisk=1; Requirements=true]`)
	res, err := sc.RequestClaim(ctx, &hstartd.ClaimRequest{RequestAd: ad, SchedulerAddr: "<127.0.0.1:1>", AliveInterval: 300})
	if err != nil {
		return false, err
	}
	return res.OK, nil
}

// stillServing fails the test if the startd shut down: daemon.Serve
// returned, or the command socket no longer answers.
func (as *authzStartd) stillServing(sec *security.SecurityConfig) {
	as.t.Helper()
	if _, err := as.queryAds(sec); err != nil {
		as.t.Fatalf("startd no longer serving: %v", err)
	}
	select {
	case <-as.served:
		as.t.Fatalf("startd shut down (Serve returned %v)", as.serveErr)
	default:
	}
}

// waitDenial returns the attributes of the next PERMISSION DENIED record.
func (as *authzStartd) waitDenial() map[string]string {
	as.t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case r := <-as.records:
			if r.Message != "PERMISSION DENIED" {
				continue
			}
			attrs := map[string]string{}
			r.Attrs(func(a slog.Attr) bool {
				attrs[a.Key] = a.Value.String()
				return true
			})
			return attrs
		case <-timeout:
			as.t.Fatal("no PERMISSION DENIED was logged")
			return nil
		}
	}
}

// expectDenial checks the next denial names the command, level, user and
// deciding knobs.
func (as *authzStartd) expectDenial(command, level, user, allowKnob, denyKnob string) {
	as.t.Helper()
	got := as.waitDenial()
	want := map[string]string{
		"command":    command,
		"level":      level,
		"user":       user,
		"allow_knob": allowKnob,
		"deny_knob":  denyKnob,
	}
	for k, v := range want {
		if got[k] != v {
			as.t.Errorf("denial %s = %q, want %q (record %v)", k, got[k], v, got)
		}
	}
	if got["peer"] == "" {
		as.t.Errorf("denial names no peer (record %v)", got)
	}
}

// TestAuthzAdministratorCommands: an identity outside ALLOW_ADMINISTRATOR
// cannot reconfigure or shut down the startd (the handlers never run); one
// inside it can.
func TestAuthzAdministratorCommands(t *testing.T) {
	as := startAuthzStartd(t, map[string]string{
		"ALLOW_ADMINISTRATOR": "admin@pool",
		"ALLOW_READ":          "*",
	})

	as.send(as.as("alice@pool"), commands.DC_RECONFIG)
	if n := as.reconfigs.Load(); n != 0 {
		t.Fatalf("reconfig ran %d times after a refused DC_RECONFIG, want 0", n)
	}
	as.expectDenial("DC_RECONFIG", "ADMINISTRATOR", "alice@pool", "ALLOW_ADMINISTRATOR", "")

	as.send(as.as("alice@pool"), commands.DC_OFF_GRACEFUL)
	as.stillServing(as.as("alice@pool"))
	as.expectDenial("DC_OFF_GRACEFUL", "ADMINISTRATOR", "alice@pool", "ALLOW_ADMINISTRATOR", "")

	as.send(as.as("admin@pool"), commands.DC_RECONFIG)
	if n := as.reconfigs.Load(); n != 1 {
		t.Fatalf("reconfig ran %d times after admin@pool's DC_RECONFIG, want 1", n)
	}

	as.send(as.as("admin@pool"), commands.DC_OFF_FAST)
	select {
	case <-as.served:
		if as.serveErr != nil {
			t.Fatalf("Serve after DC_OFF_FAST = %v, want nil", as.serveErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("startd did not shut down after admin@pool's DC_OFF_FAST")
	}
}

// TestAuthzDenyOverridesAllow: DENY_ADMINISTRATOR refuses an identity
// ALLOW_ADMINISTRATOR admits, and leaves the others admitted.
func TestAuthzDenyOverridesAllow(t *testing.T) {
	as := startAuthzStartd(t, map[string]string{
		"ALLOW_ADMINISTRATOR": "*@pool",
		"DENY_ADMINISTRATOR":  "bob@pool",
		"ALLOW_READ":          "*",
	})

	as.send(as.as("bob@pool"), commands.DC_RECONFIG)
	if n := as.reconfigs.Load(); n != 0 {
		t.Fatalf("reconfig ran %d times for bob@pool (in DENY_ADMINISTRATOR), want 0", n)
	}
	as.expectDenial("DC_RECONFIG", "ADMINISTRATOR", "bob@pool", "ALLOW_ADMINISTRATOR", "DENY_ADMINISTRATOR")

	as.send(as.as("alice@pool"), commands.DC_RECONFIG)
	if n := as.reconfigs.Load(); n != 1 {
		t.Fatalf("reconfig ran %d times for alice@pool, want 1", n)
	}
}

// TestAuthzReadUnderAllowReadStar: with ALLOW_READ = *, QUERY_STARTD_ADS
// returns the slots to an identity with no other rights and to an anonymous
// peer; with ALLOW_READ restricted, others are refused.
func TestAuthzReadUnderAllowReadStar(t *testing.T) {
	as := startAuthzStartd(t, map[string]string{
		"ALLOW_READ":          "*",
		"ALLOW_ADMINISTRATOR": "admin@pool",
		"ALLOW_DAEMON":        "schedd@pool",
	})
	for _, who := range []string{"bob@pool", ""} {
		ads, err := as.queryAds(as.as(who))
		if err != nil {
			t.Fatalf("QUERY_STARTD_ADS as %q: %v", who, err)
		}
		if len(ads) != 2 {
			t.Fatalf("QUERY_STARTD_ADS as %q returned %d ads, want 2", who, len(ads))
		}
	}

	as = startAuthzStartd(t, map[string]string{"ALLOW_READ": "alice@pool"})
	for _, who := range []string{"bob@pool", ""} {
		if ads, err := as.queryAds(as.as(who)); err == nil {
			t.Fatalf("QUERY_STARTD_ADS as %q (outside ALLOW_READ) returned %d ads, want refused", who, len(ads))
		}
		user := who
		if user == "" {
			user = "unauthenticated@unmapped"
		}
		as.expectDenial("QUERY_STARTD_ADS", "READ", user, "ALLOW_READ", "")
	}
	if ads, err := as.queryAds(as.as("alice@pool")); err != nil || len(ads) != 2 {
		t.Fatalf("QUERY_STARTD_ADS as alice@pool = %d ads, %v; want 2", len(ads), err)
	}
}

// TestAuthzFSIdentityInUIDDomain: an FS-authenticated peer is authorized as
// user@UID_DOMAIN, so an ALLOW_READ entry in that domain admits it and one in
// another domain does not.
func TestAuthzFSIdentityInUIDDomain(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skipf("no current user: %v", err)
	}
	fs := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
	}
	knobs := map[string]string{
		"UID_DOMAIN":                      "ep.test",
		"SEC_READ_AUTHENTICATION":         "REQUIRED",
		"SEC_READ_AUTHENTICATION_METHODS": "FS",
	}

	knobs["ALLOW_READ"] = me.Username + "@ep.test"
	as := startAuthzStartd(t, knobs)
	fs.SessionCache = security.NewSessionCache()
	if ads, err := as.queryAds(fs); err != nil || len(ads) != 2 {
		t.Fatalf("QUERY_STARTD_ADS over FS with ALLOW_READ = %s@ep.test = %d ads, %v; want 2", me.Username, len(ads), err)
	}

	knobs["ALLOW_READ"] = me.Username + "@other.test"
	as = startAuthzStartd(t, knobs)
	fs.SessionCache = security.NewSessionCache()
	if ads, err := as.queryAds(fs); err == nil {
		t.Fatalf("QUERY_STARTD_ADS over FS outside ALLOW_READ returned %d ads, want refused", len(ads))
	}
	as.expectDenial("QUERY_STARTD_ADS", "READ", me.Username+"@ep.test", "ALLOW_READ", "")
}

// TestAuthzPerLevelSecurity: each command is negotiated under the
// SEC_<level>_* policy of its level. With authentication required at
// ADMINISTRATOR only, an anonymous peer cannot reconfigure even under
// ALLOW_ADMINISTRATOR = *, an authenticated one can, and an anonymous peer
// still queries at READ although DAEMON (the server's base policy) requires
// authentication.
func TestAuthzPerLevelSecurity(t *testing.T) {
	as := startAuthzStartd(t, map[string]string{
		"SEC_ADMINISTRATOR_AUTHENTICATION": "REQUIRED",
		"SEC_DAEMON_AUTHENTICATION":        "REQUIRED",
		"ALLOW_ADMINISTRATOR":              "*",
		"ALLOW_READ":                       "*",
	})
	if cl, ctx, err := as.dial(as.as(""), commands.DC_RECONFIG); err == nil {
		_ = message.NewMessageForStream(cl.GetStream()).FinishMessage(ctx)
		_, _ = message.NewMessageFromStream(cl.GetStream()).GetInt(ctx)
	}
	if n := as.reconfigs.Load(); n != 0 {
		t.Fatalf("anonymous DC_RECONFIG ran reconfig %d times, want 0", n)
	}
	if ads, err := as.queryAds(as.as("")); err != nil || len(ads) != 2 {
		t.Fatalf("anonymous QUERY_STARTD_ADS = %d ads, %v; want 2", len(ads), err)
	}
	as.send(as.token("admin@pool"), commands.DC_RECONFIG)
	if n := as.reconfigs.Load(); n != 1 {
		t.Fatalf("authenticated DC_RECONFIG ran reconfig %d times, want 1", n)
	}
}

// TestAuthzReconfigReloads: DC_RECONFIG reloads the configuration file and
// rebuilds the policy, so a changed ALLOW_READ (here its _STARTD variant)
// decides the next command.
func TestAuthzReconfigReloads(t *testing.T) {
	as := startAuthzStartd(t, map[string]string{
		"ALLOW_ADMINISTRATOR": "admin@pool",
		"ALLOW_READ":          "alice@pool",
	})
	if _, err := as.queryAds(as.as("bob@pool")); err == nil {
		t.Fatal("QUERY_STARTD_ADS as bob@pool succeeded before reconfig, want refused")
	}
	as.waitDenial()

	as.writeConfig(map[string]string{
		"ALLOW_ADMINISTRATOR": "admin@pool",
		"ALLOW_READ":          "alice@pool",
		"ALLOW_READ_STARTD":   "bob@pool",
	})
	as.send(as.as("admin@pool"), commands.DC_RECONFIG)

	if ads, err := as.queryAds(as.as("bob@pool")); err != nil || len(ads) != 2 {
		t.Fatalf("QUERY_STARTD_ADS as bob@pool after reconfig = %d ads, %v; want 2", len(ads), err)
	}
	if _, err := as.queryAds(as.as("alice@pool")); err == nil {
		t.Fatal("QUERY_STARTD_ADS as alice@pool succeeded after reconfig dropped her, want refused")
	}
	as.expectDenial("QUERY_STARTD_ADS", "READ", "alice@pool", "ALLOW_READ_STARTD", "")
}

// TestAuthzClaimSessionHole: the identity of the claim sessions the startd
// mints holds DAEMON while SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION is on,
// so a schedd claims a slot over its claim session whatever ALLOW_DAEMON
// says; another identity is still decided by ALLOW_DAEMON. Turning the knob
// off, and reconfiguring, closes the hole.
func TestAuthzClaimSessionHole(t *testing.T) {
	knobs := map[string]string{
		"ALLOW_DAEMON":                             "schedd@pool",
		"ALLOW_ADMINISTRATOR":                      "admin@pool",
		"SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION": "FALSE",
	}
	as := startAuthzStartd(t, knobs)

	if ok, err := as.claimSlot(); err == nil && ok {
		t.Fatal("claim over the claim session granted with SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION off, want refused")
	}
	as.expectDenial("REQUEST_CLAIM", "DAEMON", security.SubmitSideMatchSessionFQU, "ALLOW_DAEMON", "")

	delete(knobs, "SEC_ENABLE_MATCH_PASSWORD_AUTHENTICATION")
	as.writeConfig(knobs)
	as.send(as.as("admin@pool"), commands.DC_RECONFIG)

	ok, err := as.claimSlot()
	if err != nil || !ok {
		t.Fatalf("claim over the claim session = %v, %v; want granted", ok, err)
	}

	if code, err := as.requestClaim(as.as("alice@pool")); err == nil {
		t.Fatalf("REQUEST_CLAIM as alice@pool (outside ALLOW_DAEMON) answered %d, want refused", code)
	}
	as.expectDenial("REQUEST_CLAIM", "DAEMON", "alice@pool", "ALLOW_DAEMON", "")
	if _, err := as.requestClaim(as.as("schedd@pool")); err != nil {
		t.Fatalf("REQUEST_CLAIM as schedd@pool (in ALLOW_DAEMON): %v", err)
	}

	for _, perm := range []string{"DAEMON", "WRITE", "READ"} {
		if !as.az.Authorize(perm, "127.0.0.1:1", security.SubmitSideMatchSessionFQU) {
			t.Errorf("%s not authorized at %s", security.SubmitSideMatchSessionFQU, perm)
		}
	}
	for _, perm := range []string{"ADMINISTRATOR", "NEGOTIATOR"} {
		if as.az.Authorize(perm, "127.0.0.1:1", security.SubmitSideMatchSessionFQU) {
			t.Errorf("%s authorized at %s; the C++ startd grants it DAEMON only", security.SubmitSideMatchSessionFQU, perm)
		}
	}
}

// TestAuthzFamilySession: condor_master's family session holds the levels
// DaemonCore grants it whatever ALLOW_/DENY_ say, so it can reconfigure the
// startd; another condor identity is still decided by the lists.
func TestAuthzFamilySession(t *testing.T) {
	as := startAuthzStartd(t, map[string]string{
		"ALLOW_ADMINISTRATOR": "admin@pool",
		"DENY_ADMINISTRATOR":  "condor@*",
		"ALLOW_READ":          "*",
	})
	as.send(as.as("condor@family"), commands.DC_RECONFIG)
	if n := as.reconfigs.Load(); n != 1 {
		t.Fatalf("reconfig ran %d times for condor@family, want 1", n)
	}
	as.send(as.as("condor@pool"), commands.DC_RECONFIG)
	if n := as.reconfigs.Load(); n != 1 {
		t.Fatalf("reconfig ran %d times after condor@pool's refused DC_RECONFIG, want 1", n)
	}
	as.expectDenial("DC_RECONFIG", "ADMINISTRATOR", "condor@pool", "ALLOW_ADMINISTRATOR", "DENY_ADMINISTRATOR")

	for _, perm := range []string{"ADMINISTRATOR", "DAEMON", "NEGOTIATOR", "WRITE", "READ"} {
		for _, who := range []string{"condor@family", "condor@parent"} {
			if perm == "NEGOTIATOR" && who == "condor@parent" {
				continue
			}
			if !as.az.Authorize(perm, "127.0.0.1:1", who) {
				t.Errorf("%s not authorized at %s", who, perm)
			}
		}
		if perm != "READ" && as.az.Authorize(perm, "127.0.0.1:1", "condor@pool") {
			t.Errorf("condor@pool authorized at %s with no ALLOW_%s", perm, perm)
		}
	}
	if as.az.Authorize("NEGOTIATOR", "127.0.0.1:1", "condor@parent") {
		t.Error("condor@parent authorized at NEGOTIATOR; DaemonCore grants it ADMINISTRATOR and DAEMON only")
	}
}

// TestAuthzAdvertisesNegotiatedCommandOnly: the post-auth reply lists only
// the negotiated command, so a C++ client negotiates a new session for each
// other command instead of resuming one it would then re-authenticate on.
func TestAuthzAdvertisesNegotiatedCommandOnly(t *testing.T) {
	as := startAuthzStartd(t, map[string]string{
		"ALLOW_ADMINISTRATOR": "*",
		"ALLOW_DAEMON":        "*",
		"ALLOW_READ":          "*",
	})
	cl, _, err := as.dial(as.token("alice@pool"), commands.QUERY_STARTD_ADS)
	if err != nil {
		t.Fatal(err)
	}
	if got := cl.GetSecurityNegotiation().ValidCommands; got != "5" {
		t.Fatalf("post-auth ValidCommands = %q, want only QUERY_STARTD_ADS (5)", got)
	}
}

// TestCommandLevelsMatchCxx pins the level of every command the startd
// serves, and that none is negotiated with authentication forced, to the C++
// startd's registration (startd_main.cpp; DaemonCore's daemon_core_main.cpp
// for DC_*). No C++ startd command is registered with force_authentication.
func TestCommandLevelsMatchCxx(t *testing.T) {
	as := startAuthzStartd(t, nil)
	if as.srv.SecurityConfigForCommand == nil {
		t.Fatal("no per-level security policy: every command is negotiated at DAEMON")
	}
	pinned := map[int]bool{}
	for _, tc := range cxxLevels {
		pinned[tc.cmd] = true
		name := commandName(tc.cmd)
		if perms := as.srv.CommandPerms(tc.cmd); len(perms) != 1 || perms[0] != tc.level {
			t.Errorf("%s registered at %v, want [%s] (%s)", name, perms, tc.level, tc.cxx)
		}
		got := as.srv.SecurityConfigForCommand(tc.cmd)
		if got == nil {
			t.Errorf("%s has no per-level security policy", name)
			continue
		}
		if got.Authentication == security.SecurityRequired {
			t.Errorf("%s negotiated with authentication required; the C++ startd does not force it", name)
		}
	}
	for cmd := 0; cmd < 100000; cmd++ {
		if len(as.srv.CommandPerms(cmd)) > 0 && !pinned[cmd] {
			t.Errorf("%s (%d) is registered but not pinned to a C++ registration", commandName(cmd), cmd)
		}
	}
}

// cxxLevels are the C++ registrations of the commands this startd serves.
var cxxLevels = []struct {
	cmd   int
	level string
	cxx   string
}{
	{commands.QUERY_STARTD_ADS, "READ", "startd_main.cpp:356"},
	{commands.GIVE_STATE, "READ", "startd_main.cpp:348"},
	{claim.CmdActivateClaim, "DAEMON", "startd_main.cpp:370"},
	{claim.CmdRequestClaim, "DAEMON", "startd_main.cpp:373"},
	{claim.CmdReleaseClaim, "DAEMON", "startd_main.cpp:376"},
	{claim.CmdDeactivateClaim, "DAEMON", "startd_main.cpp:329"},
	{claim.CmdDeactivateClaimForcibly, "DAEMON", "startd_main.cpp:333"},
	{claim.CmdDeactivateClaimJobDone, "DAEMON", "startd_main.cpp:337"},
	{claim.CmdDeactivateFinalXfer, "DAEMON", "startd_main.cpp:421"},
	{claim.CmdMatchInfo, "NEGOTIATOR", "startd_main.cpp:427"},
	{reconnect.CACmd, "WRITE", "startd_main.cpp:435"},
	{commands.DC_RECONFIG, "ADMINISTRATOR", "daemon_core_main.cpp:4290"},
	{commands.DC_RECONFIG_FULL, "ADMINISTRATOR", "daemon_core_main.cpp:4294"},
	{commands.DC_OFF_FAST, "ADMINISTRATOR", "daemon_core_main.cpp:4319"},
	{commands.DC_OFF_GRACEFUL, "ADMINISTRATOR", "daemon_core_main.cpp:4323"},
	{commands.DC_OFF_PEACEFUL, "ADMINISTRATOR", "daemon_core_main.cpp:4331"},
	{commands.DC_NOP, "ALLOW", "daemon_core_main.cpp:4347"},
	{commands.DC_NOP_READ, "READ", "daemon_core_main.cpp:4355"},
	{commands.DC_NOP_WRITE, "WRITE", "daemon_core_main.cpp:4359"},
	{commands.DC_NOP_NEGOTIATOR, "NEGOTIATOR", "daemon_core_main.cpp:4363"},
}

// TestLogDenialIgnoresOtherErrors: only authorization refusals are logged as
// PERMISSION DENIED.
func TestLogDenialIgnoresOtherErrors(t *testing.T) {
	records := make(chan slog.Record, 4)
	az, err := newStartdAuthz(config.NewEmpty())
	if err != nil {
		t.Fatal(err)
	}
	az.logDenial(slog.New(&recordHandler{ch: records}), nil, "127.0.0.1:1",
		errors.New("cedar/server: command 60004 (DC_RECONFIG) refused: session (authenticated=false encrypted=false) does not meet the command's security level"))
	if len(records) != 0 {
		t.Errorf("logged %d records for a security-level refusal, want 0", len(records))
	}
}

func mustParse(t *testing.T, s string) *classad.ClassAd {
	t.Helper()
	ad, err := classad.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ad
}

// recordHandler is a slog.Handler that hands every record to a channel.
type recordHandler struct{ ch chan slog.Record }

func (h *recordHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordHandler) Handle(_ context.Context, r slog.Record) error {
	select {
	case h.ch <- r.Clone():
	default:
	}
	return nil
}
func (h *recordHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordHandler) WithGroup(string) slog.Handler      { return h }
