package version

import "fmt"

// These are set via -ldflags at build time.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

func String() string {
	if Version == "" {
		return "dev"
	}
	// Compact but still useful for local binaries.
	if Commit != "none" && Date != "unknown" {
		return fmt.Sprintf("%s (%s, %s)", Version, Commit, Date)
	}
	return Version
}
