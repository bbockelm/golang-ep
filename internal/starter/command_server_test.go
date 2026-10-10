package starter

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/cedar/stream"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/syscalls"

	"github.com/bbockelm/golang-ep/internal/reconnect"
)

// reconnectFixture is a starter command server plus a stand-in for Run that
// accepts every handoff it is offered (as Run does) and records it, so a test
// observes directly whether the job's syscall socket was handed to the caller.
type reconnectFixture struct {
	cs       *commandServer
	handoffs chan *reconnectHandoff
}

func newReconnectFixture(t *testing.T, ctx context.Context) *reconnectFixture {
	t.Helper()
	log, _ := logging.New(nil)
	cs, err := newCommandServer(ctx, "127.0.0.1:0", log)
	if err != nil {
		t.Fatalf("newCommandServer: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	f := &reconnectFixture{cs: cs, handoffs: make(chan *reconnectHandoff, 4)}
	go func() {
		for {
			select {
			case ho := <-cs.reconnectCh:
				f.handoffs <- ho // recorded before the ack, so before the reply
				ho.ack <- nil
			case <-ctx.Done():
				return
			}
		}
	}()
	return f
}

// mintClaim mints a claim id carrying an AES claim session.
func mintClaim(t *testing.T, seq int) string {
	t.Helper()
	mc, err := security.MintClaimSession(security.NewSessionCache(), security.MintClaimOptions{
		Sinful: "<127.0.0.1:9618>", Birthdate: time.Now().Unix(), SequenceNum: seq,
	})
	if err != nil {
		t.Fatalf("MintClaimSession: %v", err)
	}
	return mc.ClaimID()
}

// register installs claimID's reconnect session on the command server exactly
// as get_sec_session_info would deliver it.
func (f *reconnectFixture) register(t *testing.T, claimID string) {
	t.Helper()
	cid := security.ParseClaimIDStrict(claimID)
	if err := f.cs.RegisterReconnectSession(&syscalls.SecSessionInfo{
		ReconnectID:   cid.SecSessionID(),
		ReconnectInfo: cid.SecSessionInfo(),
		ReconnectKey:  cid.SecSessionKey(),
	}); err != nil {
		t.Fatalf("RegisterReconnectSession: %v", err)
	}
}

// assertNoHandoff fails if Run was ever offered a connection.
func (f *reconnectFixture) assertNoHandoff(t *testing.T) {
	t.Helper()
	select {
	case ho := <-f.handoffs:
		t.Fatalf("syscall socket handed off (shadow %q, transfer %q)", ho.shadowAddr, ho.transferSocket)
	default:
	}
}

// dialClaim connects to the command port the way a reconnecting shadow does:
// resuming claimID's claim session, with no fresh handshake.
func dialClaim(ctx context.Context, addr, claimID string) (*client.HTCondorClient, error) {
	cache := security.NewSessionCache()
	sesid, err := security.ImportClaimSession(cache, claimID, security.ClaimSessionOptions{PeerAddr: addr})
	if err != nil {
		return nil, err
	}
	return client.ConnectAndAuthenticate(ctx, addr, &security.SecurityConfig{
		Command:      reconnect.CACmd,
		PeerName:     addr,
		SessionCache: cache,
		SessionID:    sesid,
	})
}

// dialFS connects with a fresh FS-authenticated, encrypted handshake.
func dialFS(ctx context.Context, addr string) (*client.HTCondorClient, error) {
	return client.ConnectAndAuthenticate(ctx, addr, &security.SecurityConfig{
		Command:        reconnect.CACmd,
		PeerName:       addr,
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityRequired,
		SessionCache:   security.NewSessionCache(),
	})
}

// sendReconnect sends a CA_RECONNECT_JOB request (private TransferKey
// included, as the shadow sends it) and returns the reply ad.
func sendReconnect(ctx context.Context, st *stream.Stream) (*classad.ClassAd, error) {
	req := classad.New()
	_ = req.Set("MyType", "Command")
	_ = req.Set("TargetType", "Reply")
	_ = req.Set(reconnect.AttrCommand, reconnect.CmdReconnectJob)
	_ = req.Set(reconnect.AttrShadowIPAddr, "<127.0.0.1:7777>")
	_ = req.Set(reconnect.AttrTransferKey, "freshkey123")
	_ = req.Set(reconnect.AttrTransferSock, "<127.0.0.1:8888>")
	out := message.NewMessageForStream(st)
	if err := out.PutClassAdWithOptions(ctx, req, &message.PutClassAdConfig{
		Options: message.PutClassAdIncludePrivate,
	}); err != nil {
		return nil, err
	}
	if err := out.FinishMessage(ctx); err != nil {
		return nil, err
	}
	in := message.NewMessageFromStream(st)
	reply, err := in.GetClassAd(ctx)
	if err != nil {
		return nil, err
	}
	for {
		if _, derr := in.GetBytes(ctx, 1); derr != nil {
			break
		}
	}
	return reply, nil
}

// TestReconnectJobSwapsSyscallSocket exercises the starter's CA_RECONNECT_JOB
// server end to end over loopback: a shadow (client) resuming the claim-derived
// reconnect session dials the starter's command port, sends CA_RECONNECT_JOB,
// and the handler delivers the connection to a stand-in for Run, which "adopts"
// it as the new remote-syscall socket. The test asserts the Success reply
// (carrying StarterIpAddr + the handed-over transfer params) and that the very
// connection then carries a working starter->shadow syscall message -- i.e. the
// socket was genuinely swapped in.
func TestReconnectJobSwapsSyscallSocket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	f := newReconnectFixture(t, ctx)
	claimID := mintClaim(t, 1)
	f.register(t, claimID)

	hc, err := dialClaim(ctx, f.cs.Sinful(), claimID)
	if err != nil {
		t.Fatalf("shadow ConnectAndAuthenticate: %v", err)
	}
	defer func() { _ = hc.Close() }()
	st := hc.GetStream()

	reply, err := sendReconnect(ctx, st)
	if err != nil {
		t.Fatalf("CA_RECONNECT_JOB exchange: %v", err)
	}
	if r, _ := reply.EvaluateAttrString(reconnect.AttrResult); r != reconnect.ResultSuccess {
		es, _ := reply.EvaluateAttrString(reconnect.AttrErrorString)
		t.Fatalf("CA reply Result = %q (err %q), want Success", r, es)
	}
	if a, _ := reply.EvaluateAttrString(reconnect.AttrStarterIPAddr); a != f.cs.Sinful() {
		t.Errorf("reply StarterIpAddr = %q, want %q", a, f.cs.Sinful())
	}

	// The handoff Run received must carry the fresh transfer params.
	var ho *reconnectHandoff
	select {
	case ho = <-f.handoffs:
	case <-ctx.Done():
		t.Fatal("Run never received the reconnect handoff")
	}
	if ho.transferKey != "freshkey123" || ho.transferSocket != "<127.0.0.1:8888>" {
		t.Errorf("handoff transfer params = %q/%q, want freshkey123/<127.0.0.1:8888>", ho.transferKey, ho.transferSocket)
	}
	if ho.shadowAddr != "<127.0.0.1:7777>" {
		t.Errorf("handoff shadowAddr = %q", ho.shadowAddr)
	}

	// Prove the swapped socket is a live syscall channel: the "starter" (Run's
	// stand-in, now owning ho.stream) sends a starter->shadow message and the
	// shadow reads it off the very connection it dialed with.
	probe := message.NewMessageForStream(ho.stream)
	if err := probe.PutInt(ctx, 4242); err != nil {
		t.Fatalf("starter probe send: %v", err)
	}
	if err := probe.FinishMessage(ctx); err != nil {
		t.Fatalf("starter probe finish: %v", err)
	}
	rin := message.NewMessageFromStream(st)
	got, err := rin.GetInt(ctx)
	if err != nil {
		t.Fatalf("shadow read probe over swapped socket: %v", err)
	}
	if got != 4242 {
		t.Errorf("probe over swapped socket = %d, want 4242", got)
	}
}

// TestReconnectJobRequiresReconnectSession: CA_RECONNECT_JOB hands over the
// job's syscall socket only on a connection that resumed the job's registered
// reconnect session. Every other caller is refused NotAuthorized (or fails
// outright) and Run is never offered the connection.
func TestReconnectJobRequiresReconnectSession(t *testing.T) {
	expectNotAuthorized := func(t *testing.T, hc *client.HTCondorClient, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		defer func() { _ = hc.Close() }()
		reply, err := sendReconnect(context.Background(), hc.GetStream())
		if err != nil {
			t.Fatalf("CA_RECONNECT_JOB exchange: %v", err)
		}
		if r, _ := reply.EvaluateAttrString(reconnect.AttrResult); r != reconnect.ResultNotAuthorized {
			t.Errorf("CA reply Result = %q, want %q", r, reconnect.ResultNotAuthorized)
		}
	}

	t.Run("fresh authenticated handshake", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		f := newReconnectFixture(t, ctx)
		f.register(t, mintClaim(t, 1))
		hc, err := dialFS(ctx, f.cs.Sinful())
		expectNotAuthorized(t, hc, err)
		f.assertNoHandoff(t)
	})

	t.Run("no reconnect session registered", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		f := newReconnectFixture(t, ctx)
		hc, err := dialFS(ctx, f.cs.Sinful())
		expectNotAuthorized(t, hc, err)
		f.assertNoHandoff(t)
	})

	t.Run("another claim's session", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		f := newReconnectFixture(t, ctx)
		// An earlier claim's session is still resumable from the cache; only the
		// one registered last is this job's reconnect session.
		other := mintClaim(t, 2)
		f.register(t, other)
		f.register(t, mintClaim(t, 1))
		hc, err := dialClaim(ctx, f.cs.Sinful(), other)
		expectNotAuthorized(t, hc, err)
		f.assertNoHandoff(t)
	})

	t.Run("right session id, wrong key", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		f := newReconnectFixture(t, ctx)
		claimID := mintClaim(t, 1)
		f.register(t, claimID)
		// Same session id and info; a different key.
		forged := claimID[:strings.LastIndex(claimID, "]")+1] + "0123456789abcdef0123456789abcdef"
		hc, err := dialClaim(ctx, f.cs.Sinful(), forged)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		defer func() { _ = hc.Close() }()
		if reply, err := sendReconnect(ctx, hc.GetStream()); err == nil {
			t.Errorf("CA_RECONNECT_JOB with the wrong session key got a reply: %v", reply)
		}
		f.assertNoHandoff(t)
	})
}

// TestReconnectCommandPortRequiresAuthentication: the command port refuses an
// unauthenticated, unencrypted handshake outright (C++ CA_CMD is WRITE, which
// the default security policy authenticates and encrypts).
func TestReconnectCommandPortRequiresAuthentication(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	f := newReconnectFixture(t, ctx)
	f.register(t, mintClaim(t, 1))
	hc, err := client.ConnectAndAuthenticate(ctx, f.cs.Sinful(), &security.SecurityConfig{
		Command:        reconnect.CACmd,
		PeerName:       f.cs.Sinful(),
		Authentication: security.SecurityNever,
		Encryption:     security.SecurityNever,
		SessionCache:   security.NewSessionCache(),
	})
	if err == nil {
		_ = hc.Close()
		t.Fatal("unauthenticated, unencrypted handshake to the command port succeeded")
	}
	f.assertNoHandoff(t)
}
