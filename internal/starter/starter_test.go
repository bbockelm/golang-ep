package starter

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/stream"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/syscalls"
)

// newStreamPipe returns two cedar streams joined by a net.Pipe.
func newStreamPipe() (*stream.Stream, *stream.Stream) {
	c1, c2 := net.Pipe()
	return stream.NewStream(c1), stream.NewStream(c2)
}

// fakeShadow is a minimal in-package syscall SERVER mirroring the golang-ap
// shadow's dispatch (shadow/syscalls.go) for exactly the ops the Stage-3
// starter sends. It records what it saw so tests can assert the JobExit args
// and the syscall sequence.
type fakeShadow struct {
	t     *testing.T
	jobAd *classad.ClassAd
	done  chan struct{}

	mu             sync.Mutex
	starterAd      *classad.ClassAd
	secInfoCalled  bool
	beganExecution bool
	updates        []*classad.ClassAd
	gotExit        bool
	exitStatus     int
	exitReason     int
	exitAd         *classad.ClassAd
}

func runFakeShadow(t *testing.T, st *stream.Stream, jobAd *classad.ClassAd) *fakeShadow {
	f := &fakeShadow{t: t, jobAd: jobAd, done: make(chan struct{})}
	go f.serve(st)
	return f
}

func (f *fakeShadow) replyInt(ctx context.Context, st *stream.Stream, rval, terrno int) {
	out := message.NewMessageForStream(st)
	_ = out.PutInt(ctx, rval)
	if rval < 0 {
		_ = out.PutInt(ctx, terrno)
	}
	_ = out.FinishMessage(ctx)
}

func (f *fakeShadow) serve(st *stream.Stream) {
	defer close(f.done)
	ctx := context.Background()
	for {
		in := message.NewMessageFromStream(st)
		op, err := in.GetInt(ctx)
		if err != nil {
			return
		}
		switch op {
		case syscalls.OpGetJobInfo:
			_ = drainMessage(ctx, in)
			out := message.NewMessageForStream(st)
			_ = out.PutInt(ctx, 0)
			_ = out.PutClassAd(ctx, f.jobAd)
			_ = out.FinishMessage(ctx)
		case syscalls.OpRegisterStarterInfo:
			ad, err := in.GetClassAd(ctx)
			if err != nil {
				return
			}
			_ = drainMessage(ctx, in)
			f.mu.Lock()
			f.starterAd = ad
			f.mu.Unlock()
			f.replyInt(ctx, st, 0, 0)
		case syscalls.OpGetSecSessionInfo:
			// Mirror the golang-ap shadow with no transfer endpoint: read the
			// two session-info strings, then DECLINE (rval<0 + terrno).
			if _, err := in.GetString(ctx); err != nil {
				return
			}
			if _, err := in.GetString(ctx); err != nil {
				return
			}
			_ = drainMessage(ctx, in)
			f.mu.Lock()
			f.secInfoCalled = true
			f.mu.Unlock()
			f.replyInt(ctx, st, -1, 38 /* ENOSYS */)
		case syscalls.OpBeginExecution:
			_ = drainMessage(ctx, in)
			f.mu.Lock()
			f.beganExecution = true
			f.mu.Unlock()
			f.replyInt(ctx, st, 0, 0)
		case syscalls.OpRegisterJobInfo:
			ad, err := in.GetClassAd(ctx)
			if err != nil {
				return
			}
			_ = drainMessage(ctx, in)
			f.mu.Lock()
			f.updates = append(f.updates, ad)
			f.mu.Unlock()
			f.replyInt(ctx, st, 0, 0)
		case syscalls.OpJobExit:
			status, err := in.GetInt(ctx)
			if err != nil {
				return
			}
			reason, err := in.GetInt(ctx)
			if err != nil {
				return
			}
			ad, err := in.GetClassAd(ctx)
			if err != nil {
				return
			}
			_ = drainMessage(ctx, in)
			f.mu.Lock()
			f.gotExit = true
			f.exitStatus = status
			f.exitReason = reason
			f.exitAd = ad
			f.mu.Unlock()
			f.replyInt(ctx, st, 0, 0)
			return // job_exit is the last RPC of a run
		default:
			f.t.Errorf("fake shadow: unexpected syscall %d", op)
			_ = drainMessage(ctx, in)
			f.replyInt(ctx, st, -1, 38)
		}
	}
}

func (f *fakeShadow) snapshot() fakeShadow {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fakeShadow{
		starterAd:      f.starterAd,
		secInfoCalled:  f.secInfoCalled,
		beganExecution: f.beganExecution,
		updates:        append([]*classad.ClassAd(nil), f.updates...),
		gotExit:        f.gotExit,
		exitStatus:     f.exitStatus,
		exitReason:     f.exitReason,
		exitAd:         f.exitAd,
	}
}

// runJob drives one full starter run against the fake shadow: Activate +
// syscall handoff in, control messages out. Returns the fake's recording, the
// control messages the "startd" saw, and the sandbox dir.
func runJob(t *testing.T, jobAd *classad.ClassAd, updateInterval time.Duration) (fakeShadow, []ctrlMsg, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if updateInterval <= 0 {
		updateInterval = time.Hour // effectively off
	}
	sandbox := filepath.Join(t.TempDir(), "sandbox")

	startdT, starterT := NewInprocPair()
	defer func() { _ = startdT.Close() }()
	log, err := logging.New(nil)
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	runErr := make(chan error, 1)
	go func() {
		runErr <- Run(ctx, starterT, Options{
			Logger:         log,
			SlotName:       "slot1@testhost",
			ClaimID:        "public-claim",
			UpdateInterval: updateInterval,
			UIDDomain:      "example.net",
		})
	}()

	ctrl := startdT.Control()
	if err := WriteMessage(ctx, ctrl, MsgActivate, MarshalActivate(&ActivateMsg{
		JobAd:      jobAd, // advisory copy
		SandboxDir: sandbox,
		EnvOverlay: map[string]string{"STAGE3_OVERLAY": "yes"},
	})); err != nil {
		t.Fatalf("sending Activate: %v", err)
	}

	sysA, sysB := newStreamPipe()
	if err := startdT.PassSyscallConn(sysA); err != nil {
		t.Fatalf("PassSyscallConn: %v", err)
	}
	fake := runFakeShadow(t, sysB, jobAd)

	var msgs []ctrlMsg
	for {
		typ, ad, err := ReadMessage(ctx, ctrl)
		if err != nil {
			t.Fatalf("control read after %d messages: %v", len(msgs), err)
		}
		msgs = append(msgs, ctrlMsg{typ: typ, ad: ad})
		if typ == MsgExited {
			break
		}
	}
	if err := <-runErr; err != nil {
		t.Fatalf("starter.Run: %v", err)
	}
	select {
	case <-fake.done:
	case <-ctx.Done():
		t.Fatal("fake shadow never finished")
	}
	return fake.snapshot(), msgs, sandbox
}

// vanillaAd builds a minimal vanilla job ad running /bin/sh -c script.
func vanillaAd(script string) *classad.ClassAd {
	ad := classad.New()
	_ = ad.Set("JobUniverse", int64(5))
	_ = ad.Set("Cmd", "/bin/sh")
	_ = ad.Set("Arguments", "-c '"+script+"'")
	_ = ad.Set("Iwd", "/")
	_ = ad.Set("In", "/dev/null")
	_ = ad.Set("Out", "job.out")
	_ = ad.Set("Err", "job.err")
	_ = ad.Set("ShouldTransferFiles", "NO")
	_ = ad.Set("Environment", "JOBVAR=fromjob")
	return ad
}

// findFinal extracts the Final control message from a run's transcript.
func findFinal(t *testing.T, msgs []ctrlMsg) (status, reason int, ad *classad.ClassAd) {
	t.Helper()
	for _, m := range msgs {
		if m.typ == MsgFinal {
			ad, status, reason = ParseFinal(m.ad)
			return status, reason, ad
		}
	}
	t.Fatal("no Final control message in transcript")
	return 0, 0, nil
}

func hasMsg(msgs []ctrlMsg, typ int) bool {
	for _, m := range msgs {
		if m.typ == typ {
			return true
		}
	}
	return false
}

// TestStarterRunSuccess: the syscall sequence completes, the job runs in the
// sandbox (cwd + relative Out + env), and JobExit/Final report exit 0.
func TestStarterRunSuccess(t *testing.T) {
	// The job proves cwd==sandbox (pwd), env plumbing, and stdout redirection.
	fake, msgs, sandbox := runJob(t,
		vanillaAd(`pwd; echo "JOBVAR=$JOBVAR OVERLAY=$STAGE3_OVERLAY SCRATCH=$_CONDOR_SCRATCH_DIR"; exit 0`),
		0)

	if !fake.beganExecution {
		t.Error("shadow never saw begin_execution")
	}
	if !fake.secInfoCalled {
		t.Error("starter never called get_sec_session_info (should call + tolerate decline)")
	}
	if fake.starterAd == nil {
		t.Fatal("shadow never saw register_starter_info")
	}
	if v, _ := fake.starterAd.EvaluateAttrString("Name"); v != "slot1@testhost" {
		t.Errorf("starter ad Name = %q", v)
	}
	if v, _ := fake.starterAd.EvaluateAttrString("CondorScratchDir"); v != sandbox {
		t.Errorf("starter ad CondorScratchDir = %q, want %q", v, sandbox)
	}
	if !fake.gotExit {
		t.Fatal("shadow never saw job_exit")
	}
	if fake.exitStatus != 0 || fake.exitReason != syscalls.JobExited {
		t.Errorf("job_exit(status=%d, reason=%d), want (0, %d)", fake.exitStatus, fake.exitReason, syscalls.JobExited)
	}

	status, reason, finalAd := findFinal(t, msgs)
	if status != 0 || reason != syscalls.JobExited {
		t.Errorf("Final status/reason = %d/%d, want 0/%d", status, reason, syscalls.JobExited)
	}
	if v, ok := finalAd.EvaluateAttrInt("ExitCode"); !ok || v != 0 {
		t.Errorf("final ad ExitCode = %d (ok=%v), want 0", v, ok)
	}
	if v, ok := finalAd.EvaluateAttrBool("ExitBySignal"); !ok || v {
		t.Errorf("final ad ExitBySignal = %v (ok=%v), want false", v, ok)
	}
	if _, ok := finalAd.EvaluateAttrInt("JobPid"); !ok {
		t.Error("final ad missing JobPid")
	}
	if !hasMsg(msgs, MsgHello) {
		t.Error("no Hello in control transcript")
	}

	// The job's stdout (relative Out) landed in the sandbox: cwd + stdio wiring.
	// pwd may resolve symlinks (/private/var vs /var on macOS), so compare
	// resolved paths.
	data, err := os.ReadFile(filepath.Join(sandbox, "job.out"))
	if err != nil {
		t.Fatalf("reading job.out: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(sandbox)
	if err != nil {
		resolved = sandbox
	}
	got := string(data)
	want := resolved + "\nJOBVAR=fromjob OVERLAY=yes SCRATCH=" + sandbox + "\n"
	if got != want {
		t.Errorf("job.out = %q, want %q", got, want)
	}
}

// TestStarterRunNonzeroExit: exit 7 arrives as waitpid status 7<<8 with
// ExitCode=7 and reason JOB_EXITED.
func TestStarterRunNonzeroExit(t *testing.T) {
	fake, msgs, _ := runJob(t, vanillaAd("exit 7"), 0)
	if !fake.gotExit {
		t.Fatal("no job_exit")
	}
	if fake.exitStatus != 7<<8 {
		t.Errorf("job_exit status = %#x, want %#x (exit 7)", fake.exitStatus, 7<<8)
	}
	if fake.exitReason != syscalls.JobExited {
		t.Errorf("job_exit reason = %d, want %d", fake.exitReason, syscalls.JobExited)
	}
	_, _, finalAd := findFinal(t, msgs)
	if v, ok := finalAd.EvaluateAttrInt("ExitCode"); !ok || v != 7 {
		t.Errorf("final ad ExitCode = %d (ok=%v), want 7", v, ok)
	}
}

// TestStarterRunSignalDeath: a job killed by SIGTERM reports
// ExitBySignal/ExitSignal and the raw signal wait status; reason stays
// JOB_EXITED (no core), matching the C++ starter (the shadow reads
// ExitBySignal from the ad).
func TestStarterRunSignalDeath(t *testing.T) {
	fake, msgs, _ := runJob(t, vanillaAd("kill -TERM $$; sleep 5"), 0)
	if !fake.gotExit {
		t.Fatal("no job_exit")
	}
	if sig := fake.exitStatus & 0x7f; sig != int(syscall.SIGTERM) {
		t.Errorf("job_exit status = %#x (signal %d), want signal %d", fake.exitStatus, sig, syscall.SIGTERM)
	}
	if fake.exitReason != syscalls.JobExited {
		t.Errorf("job_exit reason = %d, want %d", fake.exitReason, syscalls.JobExited)
	}
	_, _, finalAd := findFinal(t, msgs)
	if v, ok := finalAd.EvaluateAttrBool("ExitBySignal"); !ok || !v {
		t.Errorf("final ad ExitBySignal = %v (ok=%v), want true", v, ok)
	}
	if v, ok := finalAd.EvaluateAttrInt("ExitSignal"); !ok || v != int64(syscall.SIGTERM) {
		t.Errorf("final ad ExitSignal = %d (ok=%v), want %d", v, ok, syscall.SIGTERM)
	}
	if _, ok := finalAd.EvaluateAttrInt("ExitCode"); ok {
		t.Error("final ad has ExitCode despite signal death")
	}
}

// TestStarterRunExecFailure: a nonexistent Cmd is reported as
// job_exit(status=0, reason=JOB_EXEC_FAILED=110) -- our documented choice for
// exec failures (JOB_NOT_STARTED=108 is reserved for pre-exec infra failures).
func TestStarterRunExecFailure(t *testing.T) {
	ad := vanillaAd("unused")
	_ = ad.Set("Cmd", "/nonexistent/stage3-no-such-binary")
	fake, msgs, _ := runJob(t, ad, 0)
	if !fake.gotExit {
		t.Fatal("no job_exit")
	}
	if fake.exitStatus != 0 || fake.exitReason != syscalls.JobExecFailed {
		t.Errorf("job_exit(status=%d, reason=%d), want (0, %d)", fake.exitStatus, fake.exitReason, syscalls.JobExecFailed)
	}
	if v, ok := fake.exitAd.EvaluateAttrBool("ExecFailed"); !ok || !v {
		t.Error("exit ad missing ExecFailed=true")
	}
	status, reason, _ := findFinal(t, msgs)
	if status != 0 || reason != syscalls.JobExecFailed {
		t.Errorf("Final status/reason = %d/%d, want 0/%d", status, reason, syscalls.JobExecFailed)
	}
}

// TestStarterPeriodicUpdates: with a fast update interval both the control
// Update and register_job_info fire while the job runs.
func TestStarterPeriodicUpdates(t *testing.T) {
	fake, msgs, _ := runJob(t, vanillaAd("sleep 1"), 150*time.Millisecond)
	if !hasMsg(msgs, MsgUpdate) {
		t.Error("no Update control message during a 1s job with 150ms interval")
	}
	if len(fake.updates) == 0 {
		t.Error("shadow saw no register_job_info updates")
	} else if v, _ := fake.updates[0].EvaluateAttrString("JobState"); v != "Running" {
		t.Errorf("update ad JobState = %q, want Running", v)
	}
}

// TestSplitV2Raw covers the V2-raw tokenizer against the storage format the
// submit-side quoting produces.
func TestSplitV2Raw(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a b c", []string{"a", "b", "c"}},
		{"-c 'echo hi; exit 0'", []string{"-c", "echo hi; exit 0"}},
		{"'two words' plain", []string{"two words", "plain"}},
		{"say '''hi'''", []string{"say", "'hi'"}}, // doubled quotes = literal '
		{"  padded\ttabs  ", []string{"padded", "tabs"}},
		{"''", []string{""}}, // explicit empty token
		{"A=1 B='x y'", []string{"A=1", "B=x y"}},
	}
	for _, c := range cases {
		if got := splitV2Raw(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("splitV2Raw(%q) = %#v, want %#v", c.in, got, c.want)
		}
	}
}
