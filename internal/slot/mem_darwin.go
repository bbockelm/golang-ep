//go:build darwin

package slot

import "golang.org/x/sys/unix"

// detectPhysicalMemoryMB reads hw.memsize (total physical bytes) via sysctl and
// returns it in MB.
func detectPhysicalMemoryMB() int64 {
	bytes, err := unix.SysctlUint64("hw.memsize")
	if err != nil || bytes == 0 {
		return 0
	}
	return int64(bytes / (1024 * 1024))
}
