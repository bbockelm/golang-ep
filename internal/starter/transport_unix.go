package starter

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/stream"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/sharedport"
)

// Process-mode transport: the startd and a separate condor_starter-equivalent
// process rendezvous over a per-claim Unix domain socket. Per the restart-
// survival design the STARTER binds+listens and the STARTD dials (so a
// restarted startd can redial a surviving starter in Stage 7). The control
// channel is a plaintext cedar stream over the Unix socket (it is OUR protocol,
// not the shadow's); the ACTIVATE_CLAIM syscall connection -- which is a live
// AES-GCM stream to the shadow -- is handed across by SCM_RIGHTS-passing its TCP
// fd plus the cedar crypto state (stream.ExportCryptoState) needed to rebuild
// the encrypted stream byte-exactly on the far side.
//
// Wire sequence on the Unix socket, startd -> starter:
//
//	[cedar frame] MsgActivate{...}
//	[cedar frame] MsgSyscallConnFollows{CryptoState=<base64 blob>}
//	[13-byte PASS_SOCK header][sendmsg: 1 junk byte + SCM_RIGHTS(tcp fd)]
//	... then MsgVacate*/Reattach as needed ...
//
// starter -> startd carries MsgHello/Update/Final/Exited. The starter side runs
// a relay: it owns the Unix socket, intercepts MsgSyscallConnFollows (does the
// fd receive + stream rebuild), and bridges every other control message to/from
// Run over an in-memory pipe so Run's transport contract is unchanged.

// cryptoStateAttr carries the base64-encoded stream.ExportCryptoState blob
// inside the MsgSyscallConnFollows control ad.
const cryptoStateAttr = "CryptoState"

// dialTimeout / dialBackoff bound the startd's redial of a freshly spawned
// starter's listening socket (the starter needs a moment to bind after exec).
const (
	dialTimeout = 15 * time.Second
	dialBackoff = 10 * time.Millisecond
)

// passSockHeaderLen is the fixed size of the CEDAR-framed SHARED_PORT_PASS_SOCK
// header sharedport.SendForwardedConn writes before the fd: a 5-byte cedar frame
// header + an 8-byte int payload. We read+validate it before ReceiveForwardedConn
// (which, per its contract, expects the header already consumed).
const passSockHeaderLen = 5 + 8

// sharedPortPassSock mirrors sharedport's SHARED_PORT_PASS_SOCK command id (76).
const sharedPortPassSock = 76

// marshalSyscallFollows encodes the exported crypto state into the
// MsgSyscallConnFollows control ad.
func marshalSyscallFollows(blob []byte) *classad.ClassAd {
	ad := classad.New()
	_ = ad.Set(cryptoStateAttr, base64.StdEncoding.EncodeToString(blob))
	return ad
}

// parseSyscallFollows decodes the crypto-state blob from a MsgSyscallConnFollows
// ad.
func parseSyscallFollows(ad *classad.ClassAd) ([]byte, error) {
	s, _ := ad.EvaluateAttrString(cryptoStateAttr)
	if s == "" {
		return nil, fmt.Errorf("starter: SyscallConnFollows carries no %s", cryptoStateAttr)
	}
	blob, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("starter: decoding %s: %w", cryptoStateAttr, err)
	}
	return blob, nil
}

// rawConnFd extracts the raw file-descriptor of a net.Conn (the TCP socket
// underlying the syscall stream) for SCM_RIGHTS passing. It runs fn with the fd
// held valid (via SyscallConn().Control), so the caller must complete the
// sendmsg inside fn -- the fd may be reclaimed once Control returns.
func rawConnWithFd(c net.Conn, fn func(fd uintptr) error) error {
	sc, ok := c.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return fmt.Errorf("starter: syscall conn %T does not expose a raw fd", c)
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return fmt.Errorf("starter: obtaining raw syscall conn: %w", err)
	}
	var fnErr error
	if cerr := rc.Control(func(fd uintptr) { fnErr = fn(fd) }); cerr != nil {
		return fmt.Errorf("starter: RawConn.Control: %w", cerr)
	}
	return fnErr
}

// --- startd side (dials) ---

// passReq is a pending syscall-conn handoff captured by PassSyscallConn and
// consumed by FinishActivation.
type passReq struct {
	st   *stream.Stream // the ACTIVATE connection (owned; closed after the fd is passed)
	blob []byte         // its exported crypto state
}

// unixStartd is the startd's end of a process-mode transport. It is constructed
// disconnected (holding only the socket path); Connect dials the starter.
type unixStartd struct {
	socketPath string

	mu      sync.Mutex
	conn    *net.UnixConn
	ctrl    *stream.Stream
	pending chan passReq // buffered 1; PassSyscallConn -> FinishActivation
	passed  bool
	closed  bool
}

// NewUnixStartd builds the startd's disconnected process-mode transport for the
// given per-claim socket path. Call Connect (from the supervisor) to dial.
func NewUnixStartd(socketPath string) Transport {
	return &unixStartd{
		socketPath: socketPath,
		pending:    make(chan passReq, 1),
	}
}

// Connect dials the starter's listening socket, retrying until the starter has
// bound it (bounded by dialTimeout). On success the control cedar stream is live.
func (u *unixStartd) Connect(ctx context.Context) error {
	deadline := time.Now().Add(dialTimeout)
	var d net.Dialer
	for {
		dctx, cancel := context.WithTimeout(ctx, dialBackoff*4+time.Second)
		c, err := d.DialContext(dctx, "unix", u.socketPath)
		cancel()
		if err == nil {
			uc, ok := c.(*net.UnixConn)
			if !ok {
				_ = c.Close()
				return fmt.Errorf("starter: dialed %s but got %T, want *net.UnixConn", u.socketPath, c)
			}
			u.mu.Lock()
			if u.closed {
				u.mu.Unlock()
				_ = uc.Close()
				return fmt.Errorf("starter: transport closed during Connect")
			}
			u.conn = uc
			u.ctrl = stream.NewStream(uc)
			u.mu.Unlock()
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("starter: dialing starter socket %s timed out: %w", u.socketPath, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(dialBackoff):
		}
	}
}

func (u *unixStartd) Control() *stream.Stream {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.ctrl
}

// PassSyscallConn captures the ACTIVATE connection at its clean post-OK-reply
// boundary: it exports the stream's AES-GCM crypto state (failing loudly if the
// stream is not in a passable state) and stashes it for FinishActivation. It
// does not touch the control channel, so it never races the supervisor's
// Activate write. Non-blocking (the pending channel is buffered and one-shot).
func (u *unixStartd) PassSyscallConn(st *stream.Stream) error {
	blob, err := st.ExportCryptoState()
	if err != nil {
		return fmt.Errorf("starter: exporting syscall-stream crypto state for process handoff "+
			"(stream must be encrypted, past handshake, at a clean message boundary): %w", err)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return fmt.Errorf("starter: transport closed")
	}
	if u.passed {
		return fmt.Errorf("starter: syscall conn already passed")
	}
	u.passed = true
	u.pending <- passReq{st: st, blob: blob}
	return nil
}

// FinishActivation waits for PassSyscallConn, then frames MsgSyscallConnFollows
// (carrying the crypto blob) and SCM_RIGHTS-passes the syscall TCP fd on the
// same Unix socket -- all on the supervisor goroutine, serialized after Activate.
// The startd's copy of the ACTIVATE connection is closed once the fd is passed
// (the starter holds its own dup via SCM_RIGHTS).
func (u *unixStartd) FinishActivation(ctx context.Context) error {
	var req passReq
	select {
	case req = <-u.pending:
	case <-ctx.Done():
		return ctx.Err()
	}

	ctrl := u.Control()
	if ctrl == nil {
		return fmt.Errorf("starter: FinishActivation before Connect")
	}
	if err := WriteMessage(ctx, ctrl, MsgSyscallConnFollows, marshalSyscallFollows(req.blob)); err != nil {
		_ = req.st.Close()
		return fmt.Errorf("starter: sending SyscallConnFollows: %w", err)
	}

	u.mu.Lock()
	conn := u.conn
	u.mu.Unlock()
	sendErr := rawConnWithFd(req.st.GetConnection(), func(fd uintptr) error {
		return sharedport.SendForwardedConn(ctx, conn, fd)
	})
	// The fd is now dup'd into the starter; drop the startd's reference so only
	// the starter holds the shadow socket.
	_ = req.st.Close()
	if sendErr != nil {
		return fmt.Errorf("starter: SCM_RIGHTS-passing syscall fd: %w", sendErr)
	}
	return nil
}

func (u *unixStartd) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil
	}
	u.closed = true
	// Drain a stashed-but-unsent pass so its socket does not leak.
	select {
	case req := <-u.pending:
		_ = req.st.Close()
	default:
	}
	if u.conn != nil {
		return u.conn.Close()
	}
	return nil
}

// --- starter side (listens) ---

// DefaultStartdGapLease bounds how long a process starter keeps a job running
// while its startd control channel is DOWN before self-destructing (the
// "bounded startd-gap self-destruct" of the restart-survival design). A
// restarted startd redials well within this window; only a startd that never
// comes back (and, in practice, a shadow that has also given up) lets it
// elapse. Generous by default so a slow startd restart never orphans a job.
const DefaultStartdGapLease = 20 * time.Minute

// unixStarter is the starter's end of a process-mode transport. It owns the
// listening socket for the whole life of the run and runs a DURABLE relay: it
// serves the startd's control connection, and when that connection drops (a
// startd restart or crash) it KEEPS the job running and re-accepts a redial from
// the restarted startd on the SAME socket, so Run's control channel (a pipe)
// never notices the gap. MsgSyscallConnFollows is intercepted (fd receive +
// encrypted-stream rebuild) on whichever connection carries it (the initial
// Activate); every other control message is bridged to/from Run over the pipe.
//
// It closes Run's control pipe -- letting Run observe the loss and hard-vacate --
// only on an explicit Close (normal wind-down) or when the startd-gap lease
// elapses with no redial. That is the single point where "keep the job across a
// startd restart" becomes "give up": bounded, and never during a transient gap.
type unixStarter struct {
	ln   *net.UnixListener
	log  *logging.Logger
	gap  time.Duration // startd-gap self-destruct lease

	runCtrl  *stream.Stream // pipe end handed to Run via Control()
	pumpCtrl *stream.Stream // pipe end the relay bridges

	syscallCh chan *stream.Stream
	pipeConn  net.Conn // pumpCtrl's underlying conn (closed on teardown)
	runConn   net.Conn // runCtrl's underlying conn

	mu   sync.Mutex
	conn *net.UnixConn  // current control connection (nil during a gap)
	uStr *stream.Stream // cedar over the current control connection

	closeOnce   sync.Once
	syscallOnce sync.Once
	relayCtx    context.Context
	relayStop   context.CancelFunc
}

// ListenStarter binds+listens on the per-claim socket path and accepts the
// startd's initial dialed connection (bounded by acceptTimeout), then starts the
// durable control relay (which survives startd restarts by re-accepting on the
// same socket). gapLease bounds how long a control-channel gap is tolerated
// before self-destruct (<=0 uses DefaultStartdGapLease). The returned
// StarterSide is ready for Run.
func ListenStarter(socketPath string, acceptTimeout, gapLease time.Duration, log *logging.Logger) (StarterSide, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("starter: empty socket path")
	}
	if log == nil {
		log, _ = logging.New(nil)
	}
	// Tolerate a stale socket left by a crash (mirrors sharedport.Listen).
	_ = os.Remove(socketPath)
	addr, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("starter: resolve %s: %w", socketPath, err)
	}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("starter: listen %s: %w", socketPath, err)
	}
	if acceptTimeout <= 0 {
		acceptTimeout = dialTimeout
	}
	_ = ln.SetDeadline(time.Now().Add(acceptTimeout))
	conn, err := ln.AcceptUnix()
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("starter: accepting startd connection on %s: %w", socketPath, err)
	}
	_ = ln.SetDeadline(time.Time{})

	if gapLease <= 0 {
		gapLease = DefaultStartdGapLease
	}
	runConn, pipeConn := net.Pipe()
	relayCtx, relayStop := context.WithCancel(context.Background())
	s := &unixStarter{
		ln:        ln,
		log:       log,
		gap:       gapLease,
		conn:      conn,
		uStr:      stream.NewStream(conn),
		runCtrl:   stream.NewStream(runConn),
		pumpCtrl:  stream.NewStream(pipeConn),
		syscallCh: make(chan *stream.Stream, 1),
		pipeConn:  pipeConn,
		runConn:   runConn,
		relayCtx:  relayCtx,
		relayStop: relayStop,
	}
	go s.manage()
	go s.pumpOutbound()
	return s, nil
}

// manage serves the current control connection and, on its loss, re-accepts a
// redial from a restarted startd on the same socket (bounded by the gap lease).
// It runs for the life of the run; only Close or lease expiry ends it, at which
// point it closes Run's control pipe so Run hard-vacates.
func (s *unixStarter) manage() {
	first := true
	for {
		s.mu.Lock()
		uStr := s.uStr
		conn := s.conn
		s.mu.Unlock()
		if uStr == nil {
			// Gap: wait for a redial within the lease.
			c, ok := s.reaccept()
			if !ok {
				// Lease elapsed (or Close): give up -- close the control pipe so
				// Run observes the loss and hard-vacates the job.
				s.selfDestruct()
				return
			}
			s.mu.Lock()
			s.conn = c
			s.uStr = stream.NewStream(c)
			uStr = s.uStr
			conn = c
			s.mu.Unlock()
			s.log.Info(logging.DestinationGeneral, "starter re-accepted a redial from a restarted startd")
		}
		// Serve this connection until it breaks.
		s.readConn(uStr, conn)
		if s.relayCtx.Err() != nil {
			return
		}
		// Connection dropped: enter the gap (clear the current stream so the
		// outbound pump stops writing) and loop to re-accept.
		s.mu.Lock()
		if s.conn == conn {
			s.conn = nil
			s.uStr = nil
		}
		s.mu.Unlock()
		if !first {
			s.log.Warn(logging.DestinationGeneral, "starter control channel lost; job continues, awaiting redial")
		} else {
			s.log.Warn(logging.DestinationGeneral, "starter startd control channel lost; job continues, awaiting redial")
		}
		first = false
	}
}

// reaccept waits for the next startd redial on the listening socket, bounded by
// the startd-gap lease. It returns ok=false if the lease elapses or the
// transport is closed.
func (s *unixStarter) reaccept() (*net.UnixConn, bool) {
	_ = s.ln.SetDeadline(time.Now().Add(s.gap))
	if s.relayCtx.Err() != nil {
		return nil, false
	}
	c, err := s.ln.AcceptUnix()
	if err != nil {
		// Deadline (lease elapsed) or listener closed (Close): give up.
		return nil, false
	}
	_ = s.ln.SetDeadline(time.Time{})
	return c, true
}

// readConn reads control messages off one control connection. It intercepts
// MsgSyscallConnFollows (fd receive + encrypted-stream rebuild) and forwards
// everything else to Run via the pipe. It returns when the connection breaks (or
// the transport is torn down); manage() then re-accepts.
func (s *unixStarter) readConn(uStr *stream.Stream, conn *net.UnixConn) {
	for {
		typ, ad, err := ReadMessage(s.relayCtx, uStr)
		if err != nil {
			return
		}
		if typ == MsgSyscallConnFollows {
			if err := s.receiveSyscallConn(ad, conn); err != nil {
				s.log.Warn(logging.DestinationGeneral, "receiving forwarded syscall conn failed",
					"err", err.Error())
				return
			}
			continue
		}
		if err := WriteMessage(s.relayCtx, s.pumpCtrl, typ, ad); err != nil {
			return
		}
	}
}

// pumpOutbound forwards Run's control messages (Hello/Update/Final/Exited) from
// the pipe out onto the CURRENT control connection. During a startd-gap it drops
// them best-effort (there is no startd to receive; Run never blocks), so a
// heartbeat lost across a restart is simply skipped -- the next one, or the Hello
// Run sends in reply to Reattach, reaches the redialed startd.
func (s *unixStarter) pumpOutbound() {
	for {
		typ, ad, err := ReadMessage(s.relayCtx, s.pumpCtrl)
		if err != nil {
			return
		}
		s.mu.Lock()
		uStr := s.uStr
		s.mu.Unlock()
		if uStr == nil {
			continue // startd-gap: drop
		}
		if err := WriteMessage(s.relayCtx, uStr, typ, ad); err != nil {
			// This connection just broke; drop and let manage() re-accept.
			continue
		}
	}
}

// selfDestruct closes Run's control pipe so Run observes the control channel as
// gone and hard-vacates the job (the lease elapsed with no redial).
func (s *unixStarter) selfDestruct() {
	s.log.Warn(logging.DestinationGeneral,
		"startd-gap lease elapsed with no redial; self-destructing (hard-vacating job)")
	_ = s.runConn.Close()
	s.closeSyscallCh()
}

// receiveSyscallConn consumes the SHARED_PORT_PASS_SOCK header, recvmsg's the
// forwarded TCP fd, rebuilds the encrypted cedar stream from the exported crypto
// state, and delivers it to SyscallConn waiters.
func (s *unixStarter) receiveSyscallConn(ad *classad.ClassAd, conn *net.UnixConn) error {
	blob, err := parseSyscallFollows(ad)
	if err != nil {
		return err
	}
	if err := readPassSockHeader(conn); err != nil {
		return err
	}
	c, err := sharedport.ReceiveForwardedConn(conn)
	if err != nil {
		return fmt.Errorf("starter: receiving forwarded syscall fd: %w", err)
	}
	sysStream, err := stream.NewStreamWithCryptoState(c, blob)
	if err != nil {
		_ = c.Close()
		return fmt.Errorf("starter: rebuilding encrypted syscall stream from crypto state: %w", err)
	}
	select {
	case s.syscallCh <- sysStream:
	default:
		_ = sysStream.Close()
		return fmt.Errorf("starter: duplicate syscall conn")
	}
	return nil
}

// readPassSockHeader reads and validates the fixed 13-byte CEDAR-framed
// SHARED_PORT_PASS_SOCK header sharedport.SendForwardedConn writes ahead of the
// fd (sharedport's own reader is unexported, so we mirror it here).
func readPassSockHeader(r io.Reader) error {
	var hdr [passSockHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return fmt.Errorf("starter: reading PASS_SOCK header: %w", err)
	}
	length := binary.BigEndian.Uint32(hdr[1:5])
	if length != 8 {
		return fmt.Errorf("starter: PASS_SOCK header length %d, want 8", length)
	}
	if cmd := binary.BigEndian.Uint64(hdr[5:13]); cmd != sharedPortPassSock {
		return fmt.Errorf("starter: PASS_SOCK header command %d, want %d", cmd, sharedPortPassSock)
	}
	return nil
}

func (s *unixStarter) closeSyscallCh() {
	s.syscallOnce.Do(func() { close(s.syscallCh) })
}

func (s *unixStarter) Control() *stream.Stream { return s.runCtrl }

func (s *unixStarter) SyscallConn(ctx context.Context) (*stream.Stream, error) {
	select {
	case st, ok := <-s.syscallCh:
		if !ok || st == nil {
			return nil, fmt.Errorf("starter: transport closed before syscall conn arrived")
		}
		return st, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *unixStarter) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.relayStop()
		_ = s.runConn.Close()
		_ = s.pipeConn.Close()
		s.mu.Lock()
		conn := s.conn
		s.conn = nil
		s.uStr = nil
		s.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		err = s.ln.Close() // unblocks a reaccept AcceptUnix
		// Unlink our own socket file on the way out.
		if addr, ok := s.ln.Addr().(*net.UnixAddr); ok && addr.Name != "" {
			_ = os.Remove(addr.Name)
		}
	})
	return err
}
