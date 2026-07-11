package starter

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/cedar/stream"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/syscalls"

	"github.com/bbockelm/golang-ep/internal/reconnect"
)

// commandServer is the process-mode starter's OWN cedar command port: a plain
// TCP cedar server (the starter is NOT under condor_master, so there is no
// shared-port endpoint) that serves CA_CMD=1200 / CA_RECONNECT_JOB. Its sinful
// is advertised to the shadow as StarterIpAddr in register_starter_info, so a
// reconnecting shadow -- whose schedd survived a startd restart, or whose startd
// was down past the claim lease -- can dial the starter DIRECTLY (unaffected by
// the startd) and re-attach to the still-running job.
//
// The session a reconnecting shadow presents is the claim-derived reconnect
// session (SessionID = the claim's SecSessionID). The starter learns that
// session's {id, info, key} triplet from the shadow's get_sec_session_info reply
// during the original activation and registers it here (RegisterReconnectSession)
// so the inbound resumption is recognized -- exactly mirroring how the shadow's
// file-transfer Endpoint recognizes the starter's resumed filetrans session.
type commandServer struct {
	srv   *cedarserver.Server
	cache *security.SessionCache
	ln    net.Listener
	log   *logging.Logger

	sinful atomic.Value // string

	// reconnectCh delivers an accepted CA_RECONNECT_JOB handoff to Run, which
	// swaps its remote-syscall socket onto the new connection. Buffered so the
	// handler never blocks the cedar server goroutine indefinitely.
	reconnectCh chan *reconnectHandoff

	closeOnce sync.Once
}

// reconnectHandoff is one accepted CA_RECONNECT_JOB: the connection that becomes
// the new remote-syscall socket plus the fresh transfer route the shadow handed
// over. Run acks it (nil = accepted, error = refused) so the handler can reply.
type reconnectHandoff struct {
	stream         *stream.Stream
	transferKey    string
	transferSocket string
	shadowAddr     string
	ack            chan error
}

// newCommandServer builds and starts the starter's CA command server on an
// ephemeral TCP port (bindAddr, default 127.0.0.1:0). It serves until ctx is
// cancelled. The returned server's Sinful() is valid immediately.
func newCommandServer(ctx context.Context, bindAddr string, log *logging.Logger) (*commandServer, error) {
	if bindAddr == "" {
		bindAddr = "127.0.0.1:0"
	}
	cache := security.NewSessionCache()
	secConfig := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		SessionCache:   cache,
	}
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("starter: binding command port %s: %w", bindAddr, err)
	}
	cs := &commandServer{
		srv:         cedarserver.New(secConfig),
		cache:       cache,
		ln:          ln,
		log:         log,
		reconnectCh: make(chan *reconnectHandoff, 1),
	}
	cs.sinful.Store(sinfulOf(ln.Addr()))
	cs.srv.Handle(reconnect.CACmd, cs.handleCACmd, "READ", "DAEMON")
	go func() {
		if serr := cs.srv.Serve(ctx, ln); serr != nil && ctx.Err() == nil {
			if log != nil {
				log.Warn(logging.DestinationGeneral, "starter command server stopped", "err", serr.Error())
			}
		}
	}()
	return cs, nil
}

// Sinful returns the starter's command sinful ("<ip:port>"), advertised as
// StarterIpAddr.
func (cs *commandServer) Sinful() string {
	if v, ok := cs.sinful.Load().(string); ok {
		return v
	}
	return ""
}

// RegisterReconnectSession installs the claim-derived reconnect session so an
// inbound CA_RECONNECT_JOB from the shadow resumes it (no fresh handshake). The
// triplet is the reconnect {id, info, key} from the shadow's get_sec_session_info
// reply; CreateNonNegotiatedSession applies the same HKDF/AES-GCM derivation the
// shadow's ImportClaimSession does, so both ends hold the same key.
func (cs *commandServer) RegisterReconnectSession(sec *syscalls.SecSessionInfo) error {
	if sec == nil || sec.ReconnectID == "" || sec.ReconnectKey == "" {
		return fmt.Errorf("starter: no reconnect session material to register")
	}
	entry, err := security.CreateNonNegotiatedSession(&security.InheritedSession{
		Type:        security.SessionTypeNormal,
		SessionID:   sec.ReconnectID,
		SessionInfo: sec.ReconnectInfo,
		SessionKey:  sec.ReconnectKey,
	}, "")
	if err != nil {
		return fmt.Errorf("starter: importing reconnect session: %w", err)
	}
	entry.SetInherited(true)
	cs.cache.Store(entry)
	return nil
}

// handleCACmd dispatches CA_CMD on the request ad's Command attribute. Only
// CA_RECONNECT_JOB is served by the starter.
func (cs *commandServer) handleCACmd(ctx context.Context, c *cedarserver.Conn) error {
	req, err := reconnect.ReadRequest(ctx, c, func(attr string, perr error) {
		if cs.log != nil {
			cs.log.Warn(logging.DestinationGeneral, "CA request: skipping unparseable attribute",
				"attr", attr, "err", perr.Error())
		}
	})
	if err != nil {
		return err
	}
	if cmd := reconnect.RequestCommand(req); cmd != reconnect.CmdReconnectJob {
		return reconnect.WriteReply(ctx, c.Stream, reconnect.FailureReply("unsupported CA sub-command: "+cmd))
	}

	ho := &reconnectHandoff{
		stream: c.Stream,
		ack:    make(chan error, 1),
	}
	ho.transferKey, _ = req.EvaluateAttrString(reconnect.AttrTransferKey)
	ho.transferSocket, _ = req.EvaluateAttrString(reconnect.AttrTransferSock)
	ho.shadowAddr, _ = req.EvaluateAttrString(reconnect.AttrShadowIPAddr)

	// Offer the handoff to Run. If Run is not listening (no running job) refuse.
	select {
	case cs.reconnectCh <- ho:
	case <-ctx.Done():
		return ctx.Err()
	default:
		return reconnect.WriteReply(ctx, c.Stream, reconnect.FailureReply("no running job to reconnect"))
	}

	// Wait for Run to accept (swap its syscall socket) or refuse.
	var ackErr error
	select {
	case ackErr = <-ho.ack:
	case <-ctx.Done():
		return ctx.Err()
	}
	if ackErr != nil {
		return reconnect.WriteReply(ctx, c.Stream, reconnect.FailureReply(ackErr.Error()))
	}

	// Success: publish starter info and KEEP the connection open -- it is now the
	// job's new remote-syscall socket, which Run has adopted.
	reply := reconnect.SuccessReply()
	_ = reply.Set(reconnect.AttrStarterIPAddr, cs.Sinful())
	_ = reply.Set("CondorVersion", starterCondorVersion)
	if err := reconnect.WriteReply(ctx, c.Stream, reply); err != nil {
		return err
	}
	return cedarserver.KeepOpen()
}

func (cs *commandServer) Close() error {
	var err error
	cs.closeOnce.Do(func() { err = cs.ln.Close() })
	return err
}

// sinfulOf renders a listener address as a canonical HTCondor sinful string
// ("<ip:port>"). For an unspecified bind (0.0.0.0) it substitutes the loopback
// so the address is dialable by a same-host shadow.
func sinfulOf(addr net.Addr) string {
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "<" + addr.String() + ">"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("<%s:%s>", host, port)
}
