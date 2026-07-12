package adwire

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/stream"
)

// writeAd writes an ad in HTCondor putClassAd wire form on out: PutInt(numExprs)
// then the given wire strings (a private attr is the caller passing SecretMarker
// followed by the "Name = value"), then the two trailing MyType/TargetType
// strings. numExprs counts iterations (a marker+secret pair is ONE), matching
// classad_oldnew.cpp.
func writeAd(ctx context.Context, out *message.Message, numExprs int, wireStrings []string, myType, targetType string) error {
	if err := out.PutInt(ctx, numExprs); err != nil {
		return err
	}
	for _, s := range wireStrings {
		if err := out.PutString(ctx, s); err != nil {
			return err
		}
	}
	if err := out.PutString(ctx, myType); err != nil {
		return err
	}
	if err := out.PutString(ctx, targetType); err != nil {
		return err
	}
	return out.FinishMessage(ctx)
}

// TestGetClassAdDecodesSecretMarker verifies the SECRET_MARKER framing: a
// private attribute sent as "ZKM" + a second "Name = value" string decodes to a
// single attribute, the marker is not counted as an extra expression, and the
// trailing MyType/TargetType are consumed so the message reaches EOM.
func TestGetClassAdDecodesSecretMarker(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 4 iterations: two plain attrs, one PRIVATE (marker+secret), one plain.
	wire := []string{
		`ProcId = 0`,
		`Cmd = "/bin/sh"`,
		SecretMarker, `ClaimId = "<127.0.0.1:9?sock=x>#1#1#abc"`,
		`JobUniverse = 5`,
	}
	writeErr := make(chan error, 1)
	go func() {
		out := message.NewMessageForStream(stream.NewStream(c1))
		writeErr <- writeAd(ctx, out, 4, wire, "Job", "Machine")
	}()

	in := message.NewMessageFromStream(stream.NewStream(c2))
	var skipped []string
	ad, err := GetClassAd(ctx, in, func(attr string, _ error) { skipped = append(skipped, attr) })
	if err != nil {
		t.Fatalf("GetClassAd: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(skipped) != 0 {
		t.Errorf("unexpected skipped attrs: %v", skipped)
	}
	if v, ok := ad.EvaluateAttrInt("ProcId"); !ok || v != 0 {
		t.Errorf("ProcId = %d (ok=%v), want 0", v, ok)
	}
	if v, ok := ad.EvaluateAttrString("Cmd"); !ok || v != "/bin/sh" {
		t.Errorf("Cmd = %q (ok=%v), want /bin/sh", v, ok)
	}
	if v, ok := ad.EvaluateAttrInt("JobUniverse"); !ok || v != 5 {
		t.Errorf("JobUniverse = %d (ok=%v), want 5", v, ok)
	}
	// The private attribute (after the ZKM marker) must be present and intact.
	if v, ok := ad.EvaluateAttrString("ClaimId"); !ok || v != "<127.0.0.1:9?sock=x>#1#1#abc" {
		t.Errorf("ClaimId = %q (ok=%v), want the secret value", v, ok)
	}
	// MyType/TargetType rode the wire as trailing strings (not the expr list
	// here); the reader must have consumed them without error (already asserted
	// by the clean GetClassAd return and the writer's FinishMessage succeeding).
}

// TestGetClassAdSkipsUnparseable verifies a single malformed attribute is
// skipped (reported via the callback) rather than failing the whole ad.
func TestGetClassAdSkipsUnparseable(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	wire := []string{
		`Good = 1`,
		`Bad = = = )(`, // unparseable RHS
	}
	go func() {
		out := message.NewMessageForStream(stream.NewStream(c1))
		_ = writeAd(ctx, out, 2, wire, "", "")
	}()

	in := message.NewMessageFromStream(stream.NewStream(c2))
	var skipped []string
	ad, err := GetClassAd(ctx, in, func(attr string, _ error) { skipped = append(skipped, attr) })
	if err != nil {
		t.Fatalf("GetClassAd: %v", err)
	}
	if v, ok := ad.EvaluateAttrInt("Good"); !ok || v != 1 {
		t.Errorf("Good = %d (ok=%v), want 1", v, ok)
	}
	if len(skipped) != 1 || skipped[0] != "Bad" {
		t.Errorf("skipped = %v, want [Bad]", skipped)
	}
}
