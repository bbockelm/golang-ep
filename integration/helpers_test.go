// Package integration holds end-to-end tests that run golang-ep's startd as the
// pool's condor_startd under a real condor_master, alongside a C++ collector.
// These tests skip unless the HTCondor binaries are on PATH (set PATH to the
// build's sbin+bin to run them).
package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pgrep returns the pids whose full command line contains match.
func pgrep(t *testing.T, match string) []string {
	t.Helper()
	out, _ := exec.Command("pgrep", "-f", match).CombinedOutput()
	var pids []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if p := strings.TrimSpace(line); p != "" {
			pids = append(pids, p)
		}
	}
	return pids
}

// waitGone polls until no process matches binPath or the timeout elapses.
func waitGone(binPath string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, _ := exec.Command("pgrep", "-f", binPath).CombinedOutput()
		if strings.TrimSpace(string(out)) == "" {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// runCondor runs an HTCondor tool against the harness config and returns its
// combined output, failing the test on error.
func runCondor(t *testing.T, configFile string, timeout time.Duration, name string, args ...string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not found: %v", name, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+configFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// runCondorAllowErr runs an HTCondor tool and returns its output, ignoring a
// non-zero exit (e.g. condor_status returning nothing yet).
func runCondorAllowErr(configFile string, timeout time.Duration, name string, args ...string) string {
	path, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+configFile)
	out, _ := cmd.CombinedOutput()
	return string(out)
}

func dumpLog(t *testing.T, path string) {
	t.Helper()
	if data, err := os.ReadFile(path); err == nil {
		t.Logf("=== %s ===\n%s", filepath.Base(path), data)
	} else {
		t.Logf("(could not read %s: %v)", path, err)
	}
}
