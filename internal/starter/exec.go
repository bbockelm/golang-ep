package starter

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// nullFile is HTCondor's canonical "no file" stdio path.
const nullFile = "/dev/null"

// jobProcess is a started job: the running command, its process group, and the
// stdio files to close after the wait.
type jobProcess struct {
	cmd       *exec.Cmd
	pid       int
	pgid      int
	startTime time.Time
	stdio     []*os.File
}

// closeStdio closes the job's redirected stdio files (after Wait).
func (j *jobProcess) closeStdio() {
	for _, f := range j.stdio {
		_ = f.Close()
	}
	j.stdio = nil
}

// killGroup SIGKILLs the job's whole process group (best-effort). Safe to call
// repeatedly and on every exit path -- the cleanup guarantee of the plan's
// "kill(-pgid) cleanup".
func (j *jobProcess) killGroup() {
	if j.pgid > 0 {
		_ = syscall.Kill(-j.pgid, syscall.SIGKILL)
	}
}

// termGroup SIGTERMs the job's whole process group (the graceful VacateSoft
// signal). The job is expected to catch it and shut down; the startd escalates
// to a hard kill (killGroup) if it does not exit within max-vacate.
func (j *jobProcess) termGroup() {
	if j.pgid > 0 {
		_ = syscall.Kill(-j.pgid, syscall.SIGTERM)
	}
}

// suspendGroup SIGSTOPs the job's whole process group (SUSPEND_CLAIM).
func (j *jobProcess) suspendGroup() {
	if j.pgid > 0 {
		_ = syscall.Kill(-j.pgid, syscall.SIGSTOP)
	}
}

// continueGroup SIGCONTs the job's whole process group (CONTINUE_CLAIM).
func (j *jobProcess) continueGroup() {
	if j.pgid > 0 {
		_ = syscall.Kill(-j.pgid, syscall.SIGCONT)
	}
}

// startJob launches the job described by jobAd in the activation's sandbox:
//
//   - cwd = the sandbox dir (created 0700 if needed)
//   - argv[0] = Cmd (joined with Iwd when relative), argv[1:] from the
//     Arguments (V2 raw) / Args (V1) attributes
//   - environment = the job ad's Environment/Env + the Activate overlay +
//     _CONDOR_SCRATCH_DIR / _CONDOR_SLOT_NAME / _CONDOR_JOB_IWD + TMPDIR
//     pointed at the sandbox; the starter's own environment is NOT inherited
//   - In/Out/Err resolved relative to the sandbox; empty or /dev/null ->
//     /dev/null
//   - setpgid so the whole job tree can be signaled via -pgid
func startJob(jobAd *classad.ClassAd, act *ActivateMsg, slotName string) (*jobProcess, error) {
	sandbox := act.SandboxDir
	if sandbox == "" {
		return nil, fmt.Errorf("starter: activation carries no sandbox dir")
	}
	if err := os.MkdirAll(sandbox, 0o700); err != nil {
		return nil, fmt.Errorf("starter: creating sandbox: %w", err)
	}

	cmdPath, ok := jobAd.EvaluateAttrString("Cmd")
	if !ok || cmdPath == "" {
		return nil, fmt.Errorf("starter: job ad has no Cmd")
	}
	iwd, _ := jobAd.EvaluateAttrString("Iwd")
	if !filepath.IsAbs(cmdPath) && iwd != "" {
		cmdPath = filepath.Join(iwd, cmdPath)
	}

	argv := append([]string{cmdPath}, jobArgs(jobAd)...)

	// Environment: job ad first, then the startd's overlay, then the starter's
	// own additions -- os/exec uses the LAST value for duplicate keys, so later
	// entries win.
	env := jobEnv(jobAd)
	for k, v := range act.EnvOverlay {
		env = append(env, k+"="+v)
	}
	env = append(env,
		"_CONDOR_SCRATCH_DIR="+sandbox,
		"_CONDOR_SLOT_NAME="+slotName,
		"_CONDOR_JOB_IWD="+iwd,
		"TMPDIR="+sandbox,
		"TEMP="+sandbox,
		"TMP="+sandbox,
	)

	jp := &jobProcess{}
	openStdio := func(attr string, write bool) (*os.File, error) {
		path, _ := jobAd.EvaluateAttrString(attr)
		if path == "" || path == nullFile {
			path = nullFile
		} else if !filepath.IsAbs(path) {
			path = filepath.Join(sandbox, path)
		}
		var f *os.File
		var err error
		if write {
			f, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		} else {
			f, err = os.Open(path)
		}
		if err != nil {
			return nil, fmt.Errorf("starter: opening job %s %q: %w", attr, path, err)
		}
		jp.stdio = append(jp.stdio, f)
		return f, nil
	}

	stdin, err := openStdio("In", false)
	if err != nil {
		jp.closeStdio()
		return nil, err
	}
	stdout, err := openStdio("Out", true)
	if err != nil {
		jp.closeStdio()
		return nil, err
	}
	stderr, err := openStdio("Err", true)
	if err != nil {
		jp.closeStdio()
		return nil, err
	}

	cmd := &exec.Cmd{
		Path:        argv[0],
		Args:        argv,
		Dir:         sandbox,
		Env:         env,
		Stdin:       stdin,
		Stdout:      stdout,
		Stderr:      stderr,
		SysProcAttr: &syscall.SysProcAttr{Setpgid: true},
	}
	if err := cmd.Start(); err != nil {
		jp.closeStdio()
		return nil, fmt.Errorf("starter: exec %q: %w", argv[0], err)
	}
	jp.cmd = cmd
	jp.pid = cmd.Process.Pid
	jp.pgid = cmd.Process.Pid // Setpgid makes the child its own group leader
	jp.startTime = time.Now()
	return jp, nil
}

// waitInfo is the decoded outcome of the job's waitpid.
type waitInfo struct {
	rawStatus int // the raw wait(2) status word, as job_exit's status arg
	exited    bool
	exitCode  int
	signaled  bool
	signal    int
	coreDump  bool
	userCPU   float64 // seconds
	sysCPU    float64 // seconds
}

// inspectWait decodes the ProcessState left by cmd.Wait into the raw waitpid
// status word plus the exit/signal/rusage facts the final ad advertises.
func inspectWait(ps *os.ProcessState) waitInfo {
	var info waitInfo
	if ps == nil {
		return info
	}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok {
		info.rawStatus = int(ws)
		info.exited = ws.Exited()
		info.exitCode = ws.ExitStatus()
		info.signaled = ws.Signaled()
		if info.signaled {
			info.signal = int(ws.Signal())
		}
		info.coreDump = ws.CoreDump()
	}
	if ru, ok := ps.SysUsage().(*syscall.Rusage); ok && ru != nil {
		info.userCPU = float64(ru.Utime.Sec) + float64(ru.Utime.Usec)/1e6
		info.sysCPU = float64(ru.Stime.Sec) + float64(ru.Stime.Usec)/1e6
	}
	return info
}

// buildFinalAd builds the final update ad accompanying job_exit / MsgFinal:
// ExitCode or ExitBySignal+ExitSignal, JobPid, JobStartDate, JobDuration,
// RemoteUserCpu/RemoteSysCpu (the plan's update/final-ad attribute set, minus
// the memory metrics deferred past Stage 3).
func buildFinalAd(info waitInfo, pid int, start, end time.Time) *classad.ClassAd {
	ad := classad.New()
	_ = ad.Set("ExitBySignal", info.signaled)
	if info.signaled {
		_ = ad.Set("ExitSignal", int64(info.signal))
	} else {
		_ = ad.Set("ExitCode", int64(info.exitCode))
	}
	if pid > 0 {
		_ = ad.Set("JobPid", int64(pid))
	}
	if !start.IsZero() {
		_ = ad.Set("JobStartDate", start.Unix())
		_ = ad.Set("JobDuration", end.Sub(start).Seconds())
	}
	_ = ad.Set("RemoteUserCpu", info.userCPU)
	_ = ad.Set("RemoteSysCpu", info.sysCPU)
	return ad
}

// buildUpdateAd builds the periodic Update / register_job_info ad.
func buildUpdateAd(pid int, start time.Time) *classad.ClassAd {
	ad := classad.New()
	_ = ad.Set("JobState", "Running")
	if pid > 0 {
		_ = ad.Set("JobPid", int64(pid))
	}
	if !start.IsZero() {
		_ = ad.Set("JobStartDate", start.Unix())
		_ = ad.Set("JobDuration", time.Since(start).Seconds())
	}
	return ad
}
