package starter

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/bbockelm/cedar/stream"
)

// NewInprocPair builds the goroutine-mode transport: the control channel is a
// net.Pipe (synchronous, in-memory) wrapped in cedar streams, and the syscall
// connection is handed across as a *stream.Stream pointer through a buffered
// channel -- no serialization, so the stream's buffered bytes and AES state
// survive the handoff untouched (the fd-passing hazards of process mode do not
// exist here).
//
// Both ends' Close closes the shared pipe (unblocking any reader/writer) and
// the syscall channel, so either side tearing down releases the other.
func NewInprocPair() (Transport, StarterSide) {
	c1, c2 := net.Pipe()
	shared := &inprocShared{
		syscall: make(chan *stream.Stream, 1),
	}
	sd := &inprocStartd{shared: shared, ctrl: stream.NewStream(c1), conn: c1}
	st := &inprocStarter{shared: shared, ctrl: stream.NewStream(c2), conn: c2}
	return sd, st
}

// inprocShared is the state common to both ends of an in-process pair.
type inprocShared struct {
	syscall chan *stream.Stream

	mu     sync.Mutex
	passed bool // PassSyscallConn already called
	closed bool
}

func (s *inprocShared) markPassed() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("starter: transport closed")
	}
	if s.passed {
		return fmt.Errorf("starter: syscall conn already passed")
	}
	s.passed = true
	return nil
}

// close closes the syscall channel exactly once (from either end). A syscall
// stream that was passed but never claimed by the starter (e.g. a release
// racing a just-spawned starter) is closed here so the remote shadow's read
// unblocks instead of hanging on a socket nobody owns.
func (s *inprocShared) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	select {
	case st := <-s.syscall:
		if st != nil {
			_ = st.Close()
		}
	default:
	}
	close(s.syscall)
}

// inprocStartd is the startd's end.
type inprocStartd struct {
	shared *inprocShared
	ctrl   *stream.Stream
	conn   net.Conn
}

// Connect is a no-op for goroutine mode: the net.Pipe control channel is live
// from construction.
func (t *inprocStartd) Connect(context.Context) error { return nil }

func (t *inprocStartd) Control() *stream.Stream { return t.ctrl }

// FinishActivation is a no-op for goroutine mode: PassSyscallConn already
// delivered the *stream.Stream pointer through the syscall channel.
func (t *inprocStartd) FinishActivation(context.Context) error { return nil }

func (t *inprocStartd) PassSyscallConn(st *stream.Stream) error {
	if err := t.shared.markPassed(); err != nil {
		return err
	}
	// Buffered (size 1) and guarded by markPassed, so this never blocks.
	t.shared.syscall <- st
	return nil
}

func (t *inprocStartd) Close() error {
	t.shared.close()
	return t.conn.Close()
}

// inprocStarter is the starter's end.
type inprocStarter struct {
	shared *inprocShared
	ctrl   *stream.Stream
	conn   net.Conn
}

func (t *inprocStarter) Control() *stream.Stream { return t.ctrl }

func (t *inprocStarter) SyscallConn(ctx context.Context) (*stream.Stream, error) {
	select {
	case st, ok := <-t.shared.syscall:
		if !ok {
			return nil, fmt.Errorf("starter: transport closed before syscall conn arrived")
		}
		return st, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *inprocStarter) Close() error {
	t.shared.close()
	return t.conn.Close()
}
