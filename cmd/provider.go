package cmd

import (
	"github.com/spf13/cobra"
)

// providerCmd represents the provider command (deprecated - use onboard command)
var providerCmd = &cobra.Command{
	Use:        "provider",
	Short:      "Provider management commands (deprecated)",
	Long:       `Deprecated: Use 'delegator client onboard' commands instead.`,
	Deprecated: "Use 'delegator client onboard' commands for WSP onboarding",
}

func init() {
	clientCmd.AddCommand(providerCmd)
}
