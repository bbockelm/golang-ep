// Package reconnect implements the two ClassAd (CA_CMD=1200) commands the
// Stage-7 restart-survival path rides:
//
//   - CA_LOCATE_STARTER: served by the STARTD. A reconnecting shadow (whose
//     schedd outlived a startd restart, or whose startd was down past the claim
//     lease) asks the startd, "where is the starter for my job?" The startd
//     answers with the process starter's own command sinful (StarterIpAddr).
//   - CA_RECONNECT_JOB: served by the process STARTER's own command port. The
//     shadow dials the address the startd returned and re-attaches to the still-
//     running job: the connection it dials with BECOMES the new remote-syscall
//     socket (the starter adopts it), and the request hands the starter a fresh
//     TransferKey/TransferSocket to re-point file transfer at this schedd.
//
// Both are DaemonCore command CA_CMD; the real sub-command travels as the
// request ad's Command attribute (MyType="Command", TargetType="Reply"). The
// wire is putClassAd(request, IncludePrivate)+EOM -> putClassAd(reply)+EOM, with
// the connection resuming the claim-derived security session (SessionID = the
// claim's SecSessionID; no fresh handshake). golang-ap's shadow/reconnect.go is
// the proven CLIENT of both; this package is the SERVER side.
//
// The request may carry private ZKM-encoded attributes (ClaimId, TransferKey),
// so it MUST be read with adwire.GetClassAd, never cedar's plain GetClassAd. The
// reply carries only plain attributes (the shadow reads it with cedar's
// GetClassAd), so it is written with the ordinary PutClassAd.
package reconnect

import (
	"context"
	"fmt"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/message"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/cedar/stream"
	"github.com/bbockelm/golang-htcondor/logging"

	"github.com/bbockelm/golang-ep/internal/adwire"
)

// CA command wire constants (condor_commands.h / command_strings.cpp). The
// CACmd DaemonCore command carries the sub-command as the request ad's Command
// attribute; the reply's Result attribute is "Success" on success.
const (
	CACmd            = 1200
	CmdLocateStarter = "CA_LOCATE_STARTER"
	CmdReconnectJob  = "CA_RECONNECT_JOB"
	ResultSuccess    = "Success"
	ResultFailure    = "Failure"

	// Request/reply attribute names.
	AttrCommand       = "Command"
	AttrResult        = "Result"
	AttrErrorString   = "ErrorString"
	AttrClaimID       = "ClaimId"
	AttrGlobalJobID   = "GlobalJobId"
	AttrScheddIPAddr  = "ScheddIpAddr"
	AttrStarterIPAddr = "StarterIpAddr"
	AttrShadowIPAddr  = "ShadowIpAddr"
	AttrShadowVersion = "ShadowVersion"
	AttrUIDDomain     = "UidDomain"
	AttrTransferKey   = "TransferKey"
	AttrTransferSock  = "TransferSocket"
)

// ReadRequest reads a CA_CMD request ad from the connection: putClassAd(req,
// IncludePrivate)+EOM. It uses the SECRET_MARKER-aware reader (adwire) so the
// private ClaimId/TransferKey attributes decode. For the first command on a
// connection Conn.Message is nil, so a fresh message is started off the stream.
func ReadRequest(ctx context.Context, c *cedarserver.Conn, warn func(attr string, err error)) (*classad.ClassAd, error) {
	in := c.Message
	if in == nil {
		in = message.NewMessageFromStream(c.Stream)
	}
	ad, err := adwire.GetClassAd(ctx, in, warn)
	if err != nil {
		return nil, fmt.Errorf("reconnect: reading CA request: %w", err)
	}
	return ad, nil
}

// WriteReply writes a CA reply ad + EOM (plain PutClassAd; the shadow reads it
// with cedar's GetClassAd, so the reply must carry no private attributes).
func WriteReply(ctx context.Context, st *stream.Stream, reply *classad.ClassAd) error {
	out := message.NewMessageForStream(st)
	if err := out.PutClassAd(ctx, reply); err != nil {
		return fmt.Errorf("reconnect: writing CA reply: %w", err)
	}
	return out.FinishMessage(ctx)
}

// SuccessReply builds a base {Result:"Success"} reply ad.
func SuccessReply() *classad.ClassAd {
	ad := classad.New()
	_ = ad.Set(AttrResult, ResultSuccess)
	return ad
}

// FailureReply builds a {Result:"Failure", ErrorString:...} reply ad.
func FailureReply(errStr string) *classad.ClassAd {
	ad := classad.New()
	_ = ad.Set(AttrResult, ResultFailure)
	if errStr != "" {
		_ = ad.Set(AttrErrorString, errStr)
	}
	return ad
}

// RequestCommand returns the CA sub-command from a request ad's Command attr.
func RequestCommand(ad *classad.ClassAd) string {
	v, _ := ad.EvaluateAttrString(AttrCommand)
	return v
}

// LocateResult answers a CA_LOCATE_STARTER lookup.
type LocateResult struct {
	// Found reports whether the claim is known (live or persisted).
	Found bool
	// StarterAddr is the process starter's command sinful (StarterIpAddr).
	StarterAddr string
}

// LocateFunc resolves a CA_LOCATE_STARTER request to a starter address. It is
// called from a cedar server goroutine; implementations must be concurrency
// safe (the startd core answers it by round-tripping through its event loop).
type LocateFunc func(claimID, globalJobID string) LocateResult

// StartdHandler builds the startd's CA_CMD handler. It dispatches on the request
// ad's Command attribute: CA_LOCATE_STARTER is answered from live+persisted
// claim state via locate; any other sub-command is refused.
func StartdHandler(locate LocateFunc, log *logging.Logger) cedarserver.HandlerFunc {
	return func(ctx context.Context, c *cedarserver.Conn) error {
		req, err := ReadRequest(ctx, c, func(attr string, perr error) {
			if log != nil {
				log.Warn(logging.DestinationGeneral, "CA request: skipping unparseable attribute",
					"attr", attr, "err", perr.Error())
			}
		})
		if err != nil {
			return err
		}
		cmd := RequestCommand(req)
		if cmd != CmdLocateStarter {
			if log != nil {
				log.Info(logging.DestinationGeneral, "CA_CMD: unsupported sub-command for startd", "command", cmd)
			}
			return WriteReply(ctx, c.Stream, FailureReply("unsupported CA sub-command: "+cmd))
		}
		claimID, _ := req.EvaluateAttrString(AttrClaimID)
		gjid, _ := req.EvaluateAttrString(AttrGlobalJobID)
		res := locate(claimID, gjid)
		if !res.Found || res.StarterAddr == "" {
			if log != nil {
				log.Info(logging.DestinationGeneral, "CA_LOCATE_STARTER: claim not found",
					"global_job_id", gjid, "found", res.Found, "have_addr", res.StarterAddr != "")
			}
			return WriteReply(ctx, c.Stream, FailureReply("no starter for this claim"))
		}
		reply := SuccessReply()
		_ = reply.Set(AttrStarterIPAddr, res.StarterAddr)
		if log != nil {
			log.Info(logging.DestinationGeneral, "CA_LOCATE_STARTER: located starter",
				"global_job_id", gjid, "starter", res.StarterAddr)
		}
		return WriteReply(ctx, c.Stream, reply)
	}
}
