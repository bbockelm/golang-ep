package starter

import (
	"context"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/syscalls"

	"github.com/bbockelm/golang-ep/internal/reconnect"
)

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
	log, _ := logging.New(nil)

	cs, err := newCommandServer(ctx, "127.0.0.1:0", log)
	if err != nil {
		t.Fatalf("newCommandServer: %v", err)
	}
	defer func() { _ = cs.Close() }()

	// Mint a claim; register its reconnect session on the starter's command
	// server exactly as get_sec_session_info would deliver it.
	shadowCache := security.NewSessionCache()
	mc, err := security.MintClaimSession(shadowCache, security.MintClaimOptions{
		Sinful: "<127.0.0.1:9618>", Birthdate: time.Now().Unix(), SequenceNum: 1,
	})
	if err != nil {
		t.Fatalf("MintClaimSession: %v", err)
	}
	cid := security.ParseClaimIDStrict(mc.ClaimID())
	if err := cs.RegisterReconnectSession(&syscalls.SecSessionInfo{
		ReconnectID:   cid.SecSessionID(),
		ReconnectInfo: cid.SecSessionInfo(),
		ReconnectKey:  cid.SecSessionKey(),
	}); err != nil {
		t.Fatalf("RegisterReconnectSession: %v", err)
	}

	// Stand-in for Run: accept the handoff, adopt the stream, ack.
	handoffCh := make(chan *reconnectHandoff, 1)
	go func() {
		select {
		case ho := <-cs.reconnectCh:
			handoffCh <- ho
			ho.ack <- nil
		case <-ctx.Done():
		}
	}()

	// Shadow side: resume the claim session and dial the starter's command port.
	sesid, err := security.ImportClaimSession(shadowCache, mc.ClaimID(), security.ClaimSessionOptions{
		PeerAddr: cs.Sinful(),
	})
	if err != nil {
		t.Fatalf("ImportClaimSession: %v", err)
	}
	hc, err := client.ConnectAndAuthenticate(ctx, cs.Sinful(), &security.SecurityConfig{
		Command:      reconnect.CACmd,
		PeerName:     cs.Sinful(),
		SessionCache: shadowCache,
		SessionID:    sesid,
	})
	if err != nil {
		t.Fatalf("shadow ConnectAndAuthenticate: %v", err)
	}
	defer func() { _ = hc.Close() }()
	st := hc.GetStream()

	// Send the CA_RECONNECT_JOB request (private TransferKey included).
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
		t.Fatalf("send CA request: %v", err)
	}
	if err := out.FinishMessage(ctx); err != nil {
		t.Fatalf("finish CA request: %v", err)
	}

	// Read the reply and assert success + the published fields.
	in := message.NewMessageFromStream(st)
	reply, err := in.GetClassAd(ctx)
	if err != nil {
		t.Fatalf("read CA reply: %v", err)
	}
	for {
		if _, derr := in.GetBytes(ctx, 1); derr != nil {
			break
		}
	}
	if r, _ := reply.EvaluateAttrString(reconnect.AttrResult); r != reconnect.ResultSuccess {
		es, _ := reply.EvaluateAttrString(reconnect.AttrErrorString)
		t.Fatalf("CA reply Result = %q (err %q), want Success", r, es)
	}
	if a, _ := reply.EvaluateAttrString(reconnect.AttrStarterIPAddr); a != cs.Sinful() {
		t.Errorf("reply StarterIpAddr = %q, want %q", a, cs.Sinful())
	}

	// The handoff Run received must carry the fresh transfer params.
	var ho *reconnectHandoff
	select {
	case ho = <-handoffCh:
	case <-ctx.Done():
		t.Fatal("Run never received the reconnect handoff")
	}
	if ho.transferKey != "freshkey123" || ho.transferSocket != "<127.0.0.1:8888>" {
		t.Errorf("handoff transfer params = %q/%q, want freshkey123/<127.0.0.1:8888>", ho.transferKey, ho.transferSocket)
	}
	if ho.shadowAddr != "<127.0.0.1:7777>" {
		t.Errorf("handoff shadowAddr = %q", ho.shadowAddr)
	}
	if ho.stream != st { // same underlying stream object the server kept open
		t.Log("note: handoff stream is the server-side stream (expected)")
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
