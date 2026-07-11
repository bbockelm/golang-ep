//go:build !darwin && !linux

package slot

// detectPhysicalMemoryMB has no platform probe on this OS; callers fall back to
// the MEMORY config override or a safe default.
func detectPhysicalMemoryMB() int64 { return 0 }
