// Package adwire decodes the HTCondor putClassAd wire form including the
// SECRET_MARKER framing that cedar's Message.GetClassAd does not handle.
//
// HTCondor serializes a ClassAd as an expression count followed by that many
// "Name = Value" strings, then two trailing legacy MyType/TargetType strings
// (src/condor_utils/classad_oldnew.cpp). A PRIVATE attribute (ClaimId,
// TransferKey, TransferSocket, Capability, ...) is NOT sent as a plain
// expression: it is sent as the marker string "ZKM" (SECRET_MARKER, "it's a
// Zecret Klassad, Mon!") followed by a second put_secret'd "Name = Value"
// string, and the leading count counts the marker+secret pair as a SINGLE
// iteration. cedar's GetClassAd reads the marker as a bogus expression and
// fails; every ad a real C++ shadow/schedd sends that carries a claim id or
// transfer key trips this. GetClassAd here mirrors the C++ reader so those ads
// decode -- it is the ingest path for ACTIVATE_CLAIM job ads (startd) and
// get_job_info replies (starter).
package adwire

import (
	"context"
	"fmt"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/message"
)

// SecretMarker is HTCondor's SECRET_MARKER (classad_oldnew.cpp:39).
const SecretMarker = "ZKM"

// GetClassAd reads a ClassAd off in in HTCondor putClassAd wire form, decoding
// the SECRET_MARKER private-attribute framing. skip, if non-nil, is called for
// each attribute whose value fails to parse (which is then dropped rather than
// failing the whole ad, since the classad parser need not cover every C++
// expression form for the ad to be usable); pass nil to silently skip.
func GetClassAd(ctx context.Context, in *message.Message, skip func(attr string, err error)) (*classad.ClassAd, error) {
	numExprs, err := in.GetInt(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading expression count: %w", err)
	}
	if numExprs < 0 || numExprs > 1_000_000 {
		return nil, fmt.Errorf("invalid expression count %d", numExprs)
	}
	ad := classad.New()
	for i := 0; i < numExprs; i++ {
		line, err := in.GetString(ctx)
		if err != nil {
			return nil, fmt.Errorf("reading expression %d/%d: %w", i, numExprs, err)
		}
		if line == SecretMarker {
			// A private attribute: the real (encrypted) "Name = Value" follows.
			line, err = in.GetString(ctx)
			if err != nil {
				return nil, fmt.Errorf("reading secret expression %d/%d: %w", i, numExprs, err)
			}
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if perr := insertLongForm(ad, line); perr != nil && skip != nil {
			skip(firstToken(line), perr)
		}
	}
	// Trailing legacy MyType/TargetType strings (not counted in numExprs; the
	// real MyType/TargetType ride the expression list as regular attributes).
	_, _ = in.GetString(ctx)
	_, _ = in.GetString(ctx)
	return ad, nil
}

// insertLongForm parses a single "Name = Value" long-form line and inserts it
// into ad. The RHS may itself contain '=' (inside strings/expressions), so only
// the FIRST '=' splits name from value.
func insertLongForm(ad *classad.ClassAd, line string) error {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return fmt.Errorf("no '=' in %q", line)
	}
	name := strings.TrimSpace(line[:eq])
	val := strings.TrimSpace(line[eq+1:])
	if name == "" {
		return fmt.Errorf("empty attribute name in %q", line)
	}
	expr, err := classad.ParseExpr(val)
	if err != nil {
		return err
	}
	ad.InsertExpr(name, expr)
	return nil
}

// firstToken returns the attribute name portion of a "Name = Value" line (for
// logging without leaking secret values).
func firstToken(line string) string {
	if eq := strings.IndexByte(line, '='); eq >= 0 {
		return strings.TrimSpace(line[:eq])
	}
	if len(line) > 16 {
		return line[:16]
	}
	return line
}
