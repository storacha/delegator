package cmd

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/storacha/delegator/pkg/client"
)

var (
	apiURL  string
	timeout time.Duration
)

// clientCmd represents the client command
var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Delegator CLI client",
	Long: `CLI client for interacting with the delegator API.

Provides commands for provider onboarding, verification,
and delegation management.`,
}

func init() {
	rootCmd.AddCommand(clientCmd)

	// Client-specific flags
	clientCmd.PersistentFlags().StringVar(&apiURL, "api-url", "http://localhost:8080", "delegator API base URL")
	clientCmd.PersistentFlags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
}

// newClient creates a configured delegator client
func newClient() (*client.Client, error) {
	baseURL := apiURL
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	return client.New(baseURL,
		client.WithTimeout(timeout),
		client.WithUserAgent("delegator-cli/1.0"),
	)
}

// newContext creates a context for API calls
func newContext() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	_ = cancel // We'll let the client handle timeout
	return ctx
}
