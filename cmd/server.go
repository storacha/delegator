package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/storacha/delegator/internal/server"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the delegator API server",
	Long: `Start the delegator API server that provides endpoints for WSP onboarding,
DID verification, delegation generation, and provider management.`,
	RunE: runServer,
}

func init() {
	rootCmd.AddCommand(serverCmd)

	// Server-specific flags
	serverCmd.Flags().String("host", "localhost", "server host")
	serverCmd.Flags().Int("port", 8080, "server port")
	serverCmd.Flags().String("key-file", "", "PEM file containing private key of delegator")
}

func runServer(cmd *cobra.Command, args []string) error {
	config := GetConfig()

	// Override config with command line flags
	if cmd.Flags().Changed("host") {
		host, _ := cmd.Flags().GetString("host")
		config.Server.Host = host
	}
	if cmd.Flags().Changed("port") {
		port, _ := cmd.Flags().GetInt("port")
		config.Server.Port = port
	}

	if cmd.Flags().Changed("key-file") {
		keyFilePath, _ := cmd.Flags().GetString("key-file")
		config.Onboarding.KeyFilePath = keyFilePath
	}

	// Create server instance
	srv, err := server.New(config)
	if err != nil {
		return err
	}

	// Start server in a goroutine
	go func() {
		if err := srv.Start(); err != nil {
			srv.Echo().Logger.Fatal("server start failed", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return srv.Shutdown(ctx)
}
