package reconnect

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/stream"

	"github.com/bbockelm/golang-ep/internal/adwire"
)

// TestCARequestCodecRoundTrip verifies that a CA request written the way the
// shadow writes it (putClassAd with IncludePrivate, so private ZKM attrs like
// ClaimId/TransferKey are secret-marker encoded) decodes with adwire.GetClassAd
// -- the reader our servers use. It exercises both sub-commands' field sets.
func TestCARequestCodecRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		set  func(ad *classad.ClassAd)
		want map[string]string
	}{
		{
			name: "locate_starter",
			set: func(ad *classad.ClassAd) {
				_ = ad.Set(AttrCommand, CmdLocateStarter)
				_ = ad.Set(AttrClaimID, "<127.0.0.1:9618>#1#2#[Encryption=\"YES\";]secretkey")
				_ = ad.Set(AttrGlobalJobID, "schedd#12.0#1700000000")
				_ = ad.Set(AttrScheddIPAddr, "<10.0.0.1:9618>")
			},
			want: map[string]string{
				AttrCommand:      CmdLocateStarter,
				AttrGlobalJobID:  "schedd#12.0#1700000000",
				AttrScheddIPAddr: "<10.0.0.1:9618>",
				AttrClaimID:      "<127.0.0.1:9618>#1#2#[Encryption=\"YES\";]secretkey",
			},
		},
		{
			name: "reconnect_job",
			set: func(ad *classad.ClassAd) {
				_ = ad.Set(AttrCommand, CmdReconnectJob)
				_ = ad.Set(AttrShadowIPAddr, "<10.0.0.2:9618>")
				_ = ad.Set(AttrShadowVersion, "$CondorVersion: 25.0.0$")
				_ = ad.Set(AttrUIDDomain, "example.net")
				_ = ad.Set(AttrTransferKey, "abc123deadbeef")
				_ = ad.Set(AttrTransferSock, "<10.0.0.2:12345>")
			},
			want: map[string]string{
				AttrCommand:      CmdReconnectJob,
				AttrShadowIPAddr: "<10.0.0.2:9618>",
				AttrUIDDomain:    "example.net",
				AttrTransferKey:  "abc123deadbeef", // private, ZKM-encoded on the wire
				AttrTransferSock: "<10.0.0.2:12345>",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cw, sw := net.Pipe()
			defer func() { _ = cw.Close() }()
			defer func() { _ = sw.Close() }()
			wr := stream.NewStream(cw)
			rd := stream.NewStream(sw)

			req := caRequestFor(tc.set)
			go func() {
				out := message.NewMessageForStream(wr)
				_ = out.PutClassAdWithOptions(ctx, req, &message.PutClassAdConfig{
					Options: message.PutClassAdIncludePrivate,
				})
				_ = out.FinishMessage(ctx)
			}()

			in := message.NewMessageFromStream(rd)
			got, err := adwire.GetClassAd(ctx, in, nil)
			if err != nil {
				t.Fatalf("adwire.GetClassAd: %v", err)
			}
			if cmd := RequestCommand(got); cmd != tc.want[AttrCommand] {
				t.Errorf("Command = %q, want %q", cmd, tc.want[AttrCommand])
			}
			for k, want := range tc.want {
				gv, _ := got.EvaluateAttrString(k)
				if gv != want {
					t.Errorf("attr %s = %q, want %q", k, gv, want)
				}
			}
		})
	}
}

// TestReplyBuilders checks the reply constructors and the shadow-visible fields.
func TestReplyBuilders(t *testing.T) {
	ok := SuccessReply()
	if r, _ := ok.EvaluateAttrString(AttrResult); r != ResultSuccess {
		t.Errorf("SuccessReply Result = %q, want %q", r, ResultSuccess)
	}
	_ = ok.Set(AttrStarterIPAddr, "<127.0.0.1:5000>")
	if a, _ := ok.EvaluateAttrString(AttrStarterIPAddr); a != "<127.0.0.1:5000>" {
		t.Errorf("StarterIpAddr not set on success reply")
	}

	fail := FailureReply("claim not found")
	if r, _ := fail.EvaluateAttrString(AttrResult); r != ResultFailure {
		t.Errorf("FailureReply Result = %q, want %q", r, ResultFailure)
	}
	if e, _ := fail.EvaluateAttrString(AttrErrorString); e != "claim not found" {
		t.Errorf("FailureReply ErrorString = %q", e)
	}
}

func caRequestFor(set func(*classad.ClassAd)) *classad.ClassAd {
	ad := classad.New()
	_ = ad.Set("MyType", "Command")
	_ = ad.Set("TargetType", "Reply")
	set(ad)
	return ad
}
