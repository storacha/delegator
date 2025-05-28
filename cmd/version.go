package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

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
		fmt.Printf("Delegator Service\n")
		fmt.Printf("Version: %s\n", Version)
		fmt.Printf("Commit: %s\n", Commit)
		fmt.Printf("Built: %s\n", BuildTime)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
