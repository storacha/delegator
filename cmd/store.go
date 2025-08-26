package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/storacha/go-ucanto/did"
	"github.com/storacha/delegator/internal/config"
	"github.com/storacha/delegator/internal/store"
)

var StoreCmd = &cobra.Command{
	Use:   "store",
	Short: "Manage store operations",
	Long:  `Commands for managing the DynamoDB store, including allowlist management.`,
}

var allowDIDCmd = &cobra.Command{
	Use:   "allow-did [did]",
	Short: "Add a DID to the allowlist",
	Long:  `Add a DID to the allowlist. If the DID is already in the list, the command returns success (idempotent).`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		didStr := args[0]

		// Validate DID
		parsedDID, err := did.Parse(didStr)
		if err != nil {
			return fmt.Errorf("invalid DID format: %w", err)
		}

		// Initialize store
		cfg := &config.Config{}
		if err := viper.Unmarshal(cfg); err != nil {
			return fmt.Errorf("failed to load configuration: %w", err)
		}

		db, err := store.NewDynamoDBStore(cfg.Store)
		if err != nil {
			return fmt.Errorf("failed to initialize store: %w", err)
		}

		ctx := context.Background()

		// Check if DID is already allowed
		allowed, err := db.IsAllowedDID(ctx, parsedDID)
		if err != nil {
			return fmt.Errorf("failed to check DID status: %w", err)
		}

		if allowed {
			fmt.Printf("DID %s is already allowed\n", didStr)
			return nil
		}

		// Add DID to allowlist
		err = db.AddAllowedDID(ctx, parsedDID)
		if err != nil {
			return fmt.Errorf("failed to add DID to allowlist: %w", err)
		}

		fmt.Printf("Successfully added DID %s to allowlist\n", didStr)
		return nil
	},
}

var disallowDIDCmd = &cobra.Command{
	Use:   "disallow-did [did]",
	Short: "Remove a DID from the allowlist",
	Long:  `Remove a DID from the allowlist. If the DID is not in the list, the command returns success (idempotent).`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		didStr := args[0]

		// Validate DID
		parsedDID, err := did.Parse(didStr)
		if err != nil {
			return fmt.Errorf("invalid DID format: %w", err)
		}

		// Initialize store
		cfg := &config.Config{}
		if err := viper.Unmarshal(cfg); err != nil {
			return fmt.Errorf("failed to load configuration: %w", err)
		}

		db, err := store.NewDynamoDBStore(cfg.Store)
		if err != nil {
			return fmt.Errorf("failed to initialize store: %w", err)
		}

		ctx := context.Background()

		// Check if DID is allowed
		allowed, err := db.IsAllowedDID(ctx, parsedDID)
		if err != nil {
			return fmt.Errorf("failed to check DID status: %w", err)
		}

		if !allowed {
			fmt.Printf("DID %s is not in the allowlist\n", didStr)
			return nil
		}

		// Remove DID from allowlist
		err = db.RemoveAllowedDID(ctx, parsedDID)
		if err != nil {
			return fmt.Errorf("failed to remove DID from allowlist: %w", err)
		}

		fmt.Printf("Successfully removed DID %s from allowlist\n", didStr)
		return nil
	},
}

func init() {
	// Add store flags (similar to serve command)
	StoreCmd.PersistentFlags().String("store-region", "", "AWS region for DynamoDB")
	StoreCmd.PersistentFlags().String("store-allowlist-table", "", "DynamoDB table name for allowlist")
	StoreCmd.PersistentFlags().String("store-providerinfo-table", "", "DynamoDB table name for provider info")
	StoreCmd.PersistentFlags().Uint("store-provider-weight", 1, "Default weight for registered providers")
	StoreCmd.PersistentFlags().String("store-endpoint", "", "DynamoDB endpoint (for local testing)")

	// Bind flags to viper
	cobra.CheckErr(viper.BindPFlag("store.region", StoreCmd.PersistentFlags().Lookup("store-region")))
	cobra.CheckErr(viper.BindPFlag("store.allowlist_table_name", StoreCmd.PersistentFlags().Lookup("store-allowlist-table")))
	cobra.CheckErr(viper.BindPFlag("store.providerinfo_table_name", StoreCmd.PersistentFlags().Lookup("store-providerinfo-table")))
	cobra.CheckErr(viper.BindPFlag("store.providerweight", StoreCmd.PersistentFlags().Lookup("store-provider-weight")))
	cobra.CheckErr(viper.BindPFlag("store.endpoint", StoreCmd.PersistentFlags().Lookup("store-endpoint")))

	// Add subcommands
	StoreCmd.AddCommand(allowDIDCmd)
	StoreCmd.AddCommand(disallowDIDCmd)
}
