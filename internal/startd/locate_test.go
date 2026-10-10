package startd

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"

	"github.com/bbockelm/golang-ep/internal/persist"
	"github.com/bbockelm/golang-ep/internal/reconnect"
)

// caLocate sends CA_LOCATE_STARTER to addr over the claim session of
// sessionClaim (the transport) carrying the given ClaimId/GlobalJobId, and
// returns the reply ad.
func caLocate(t *testing.T, ctx context.Context, addr, sessionClaim, claimID, gjid string) *classad.ClassAd {
	t.Helper()
	cache := security.NewSessionCache()
	sesid, err := security.ImportClaimSession(cache, sessionClaim, security.ClaimSessionOptions{PeerAddr: addr})
	if err != nil {
		t.Fatalf("ImportClaimSession: %v", err)
	}
	hc, err := client.ConnectAndAuthenticate(ctx, addr, &security.SecurityConfig{
		Command: reconnect.CACmd, PeerName: addr, SessionCache: cache, SessionID: sesid,
	})
	if err != nil {
		t.Fatalf("ConnectAndAuthenticate: %v", err)
	}
	defer func() { _ = hc.Close() }()

	req := classad.New()
	_ = req.Set("MyType", "Command")
	_ = req.Set("TargetType", "Reply")
	_ = req.Set(reconnect.AttrCommand, reconnect.CmdLocateStarter)
	if claimID != "" {
		_ = req.Set(reconnect.AttrClaimID, claimID)
	}
	if gjid != "" {
		_ = req.Set(reconnect.AttrGlobalJobID, gjid)
	}
	_ = req.Set(reconnect.AttrScheddIPAddr, "<127.0.0.1:1>")
	out := message.NewMessageForStream(hc.GetStream())
	if err := out.PutClassAdWithOptions(ctx, req, &message.PutClassAdConfig{
		Options: message.PutClassAdIncludePrivate,
	}); err != nil {
		t.Fatalf("send request: %v", err)
	}
	if err := out.FinishMessage(ctx); err != nil {
		t.Fatalf("finish request: %v", err)
	}
	reply, err := message.NewMessageFromStream(hc.GetStream()).GetClassAd(ctx)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return reply
}

// TestLocateStarterRequiresClaimID drives the startd's CA_CMD handler over
// loopback. CA_LOCATE_STARTER reveals a starter's command address only to a
// caller presenting that claim's full claim id (and, if it names one, the
// claim's own GlobalJobId), for both a live activation and a persisted record.
// A GlobalJobId alone, or another claim's id, locates nothing.
func TestLocateStarterRequiresClaimID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	addr := fmt.Sprintf("<%s>", ln.Addr().String())
	core, cache := newTestCore(t, 1, addr)

	// Live: slot 1 runs a job whose starter serves at liveAddr.
	const liveGJID, liveAddr = "schedd#1.0#1700000000", "<127.0.0.1:4444>"
	slotName := setBusyAdopted(t, core, cache, t.TempDir())
	liveClaim := core.Slots()[0].Claim().ClaimID()
	core.activations[slotName].globalJID = liveGJID
	core.activations[slotName].starterAddr = liveAddr

	// Persisted: a claim known only from the store (its startd just restarted).
	const diskGJID, diskAddr = "schedd#2.0#1700000000", "<127.0.0.1:5555>"
	store, err := persist.Open(t.TempDir())
	if err != nil {
		t.Fatalf("persist.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	core.store = store
	diskClaim, diskPub, _ := mintTestClaim(t, security.NewSessionCache(), addr, 9)
	if err := store.Put(persist.Record{
		SlotName: "slot_gone", ClaimID: diskClaim, PublicClaimID: diskPub,
		State: "Claimed", Activity: "Busy", GlobalJobID: diskGJID, StarterIpAddr: diskAddr,
	}); err != nil {
		t.Fatalf("store.Put: %v", err)
	}

	otherClaim, _, _ := mintTestClaim(t, security.NewSessionCache(), addr, 5)

	core.Start(ctx)
	t.Cleanup(core.Stop)
	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		SessionCache:   cache,
	})
	core.RegisterCommands(srv)
	go func() { _ = srv.Serve(ctx, ln) }()

	cases := []struct {
		name, claimID, gjid, wantAddr string
	}{
		{"live claim and job", liveClaim, liveGJID, liveAddr},
		{"live claim only", liveClaim, "", liveAddr},
		{"live job only", "", liveGJID, ""},
		{"other claim, live job", otherClaim, liveGJID, ""},
		{"live claim, other job", liveClaim, diskGJID, ""},
		{"persisted claim and job", diskClaim, diskGJID, diskAddr},
		{"persisted job only", "", diskGJID, ""},
		{"other claim, persisted job", otherClaim, diskGJID, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The connection itself always rides the live claim's session, so
			// only the request's ClaimId/GlobalJobId vary.
			reply := caLocate(t, ctx, addr, liveClaim, tc.claimID, tc.gjid)
			result, _ := reply.EvaluateAttrString(reconnect.AttrResult)
			got, _ := reply.EvaluateAttrString(reconnect.AttrStarterIPAddr)
			if tc.wantAddr == "" {
				if result == reconnect.ResultSuccess || got != "" {
					t.Fatalf("Result = %q, StarterIpAddr = %q; want refusal with no address", result, got)
				}
				return
			}
			if result != reconnect.ResultSuccess || got != tc.wantAddr {
				t.Fatalf("Result = %q, StarterIpAddr = %q; want Success, %q", result, got, tc.wantAddr)
			}
		})
	}
}
