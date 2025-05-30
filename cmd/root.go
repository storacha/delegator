package cmd

import (
	"fmt"
	"os"

	logging "github.com/ipfs/go-log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/storacha/delegator/internal/config"
)

var (
	cfgFile string
	v       *viper.Viper
	cfg     *config.Config
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "delegator",
	Short: "Warm Storage Provider Delegator Service",
	Long: `Delegator is a service for managing Warm Storage Provider (WSP) onboarding.

It provides secure multi-step provider registration, DID verification,
delegation generation, and FQDN validation for storage providers in the
Storacha network.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return initConfig()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize()

	// Initialize viper instance first
	v = config.New()

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.delegator/config.yaml)")
	rootCmd.PersistentFlags().String("log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().String("log-format", "json", "log format (json, text)")

	// Bind flags to viper
	if err := v.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("log-level")); err != nil {
		panic(err)
	}
	if err := v.BindPFlag("log.format", rootCmd.PersistentFlags().Lookup("log-format")); err != nil {
		panic(err)
	}
}

func initConfig() error {
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	}

	var err error
	cfg, err = config.Load(v)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.Log.Level != "" {
		lvl, err := logging.LevelFromString(cfg.Log.Level)
		if err != nil {
			return fmt.Errorf("invalid log level (%s): %w", cfg.Log.Level, err)
		}
		logging.SetAllLoggers(lvl)
	} else {
		logging.SetAllLoggers(logging.LevelInfo)
	}

	return nil
}

// GetConfig returns the loaded configuration
func GetConfig() *config.Config {
	return cfg
}

// GetViper returns the viper instance
func GetViper() *viper.Viper {
	return v
}
