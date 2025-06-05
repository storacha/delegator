package cmd

import (
	logging "github.com/ipfs/go-log"
	"github.com/spf13/cobra"
)

var verLog = logging.Logger("version")

// Build information set by ldflags
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  `Display version, commit hash, and build time information.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Since this is CLI output for user display, we're using cmd.Println
		// instead of the logging system as these aren't real logs
		cmd.Println("Delegator Service")
		cmd.Printf("Version: %s\n", Version)
		cmd.Printf("Commit: %s\n", Commit)
		cmd.Printf("Built: %s\n", BuildTime)

		// Log version info to actual logs (if logging is enabled)
		verLog.Infow("Version information requested",
			"version", Version,
			"commit", Commit,
			"build_time", BuildTime)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
