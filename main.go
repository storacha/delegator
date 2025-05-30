package main

import "github.com/storacha/delegator/cmd"

// Build information (set by ldflags)
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func main() {
	// Set build info in cmd package
	cmd.Version = Version
	cmd.Commit = Commit
	cmd.BuildTime = BuildTime

	cmd.Execute()
}
