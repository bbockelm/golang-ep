package slot

import (
	"fmt"
	"runtime"

	"github.com/bbockelm/golang-htcondor/version"
)

// condorVersionString renders the "$CondorVersion: ... $" banner tagging this
// build as golang-ep, mirroring golang-ap/golang-collector.
func condorVersionString() string {
	v := version.Get()
	return fmt.Sprintf("$CondorVersion: %s BuildID: golang-ep-%s $", v.Version, v.Commit)
}

// condorPlatformString renders the "$CondorPlatform: ... $" banner.
func condorPlatformString() string {
	return fmt.Sprintf("$CondorPlatform: %s_%s $", runtime.GOARCH, runtime.GOOS)
}
