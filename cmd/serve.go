package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/storacha/delegator/internal/services/benchmark"
	"github.com/storacha/delegator/internal/services/registrar"
	"go.uber.org/fx"

	"github.com/storacha/delegator/internal/config"
	"github.com/storacha/delegator/internal/handlers"
	"github.com/storacha/delegator/internal/providers"
	"github.com/storacha/delegator/internal/server"
	"github.com/storacha/delegator/internal/store"
)

var ServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the HTTP server",
	Long:  `Start the registrar HTTP server with configured endpoints.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		app := fx.New(
			fx.Provide(
				// Configuration
				config.NewConfig,

				func(cfg *config.Config) config.DynamoConfig {
					return cfg.Store
				},

				// Providers for complex types
				providers.ProvideSigner,
				providers.ProvideIndexingServiceWebDID,
				providers.ProvideIndexingServiceProof,
				providers.ProvideEgressTrackingServiceDID,
				providers.ProvideEgressTrackingServiceProof,
				providers.ProvideUploadServiceDID,

				// Store
				fx.Annotate(
					store.NewDynamoDBStore,
					fx.As(new(store.Store)),
				),

				// Service
				registrar.New,
				benchmark.New,

				// Handlers and Server
				handlers.NewHandlers,
				server.NewServer,
			),
			fx.Invoke(server.Start),
		)

		app.Run()
		return nil
	},
}

func init() {
	// Server flags
	ServeCmd.Flags().String("host", "0.0.0.0", "Server host")
	ServeCmd.Flags().Int("port", 8080, "Server port")

	// Store flags
	ServeCmd.Flags().String("store-region", "", "AWS region for DynamoDB")
	ServeCmd.Flags().String("store-allowlist-table", "", "DynamoDB table name for allowlist")
	ServeCmd.Flags().String("store-providerinfo-table", "", "DynamoDB table name for provider info")
	ServeCmd.Flags().Uint("store-provider-weight", 1, "Default weight for registered providers")
	ServeCmd.Flags().String("store-endpoint", "", "DynamoDB endpoint (for local testing)")

	// Service flags
	ServeCmd.Flags().String("delegator-key", "", "Multibase-encoded delegator private key")
	ServeCmd.Flags().String("delegator-key-file", "", "Path to delegator private key file")
	ServeCmd.MarkFlagsMutuallyExclusive("delegator-key", "delegator-key-file")
	ServeCmd.MarkFlagsOneRequired("delegator-key", "delegator-key-file")
	ServeCmd.Flags().String("delegator-did", "", "DID web of the delegator")

	ServeCmd.Flags().String("delegator-indexing-service-did", "", "DID of the indexing service")
	ServeCmd.Flags().String("delegator-indexing-service-proof", "", "Path to proof file from indexing service")
	ServeCmd.Flags().String("delegator-egress-tracking-service-did", "", "DID of the egress tracking service")
	ServeCmd.Flags().String("delegator-egress-tracking-service-proof", "", "Path to proof file from egress tracking service")
	ServeCmd.Flags().String("delegator-upload-service-did", "", "DID of the upload service")

	// Bind flags to viper
	cobra.CheckErr(viper.BindPFlag("server.host", ServeCmd.Flags().Lookup("host")))
	cobra.CheckErr(viper.BindPFlag("server.port", ServeCmd.Flags().Lookup("port")))

	cobra.CheckErr(viper.BindPFlag("store.region", ServeCmd.Flags().Lookup("store-region")))
	cobra.CheckErr(viper.BindPFlag("store.allowlist_table_name", ServeCmd.Flags().Lookup("store-allowlist-table")))
	cobra.CheckErr(viper.BindPFlag("store.providerinfo_table_name", ServeCmd.Flags().Lookup("store-providerinfo-table")))
	cobra.CheckErr(viper.BindPFlag("store.providerweight", ServeCmd.Flags().Lookup("store-provider-weight")))
	cobra.CheckErr(viper.BindPFlag("store.endpoint", ServeCmd.Flags().Lookup("store-endpoint")))

	cobra.CheckErr(viper.BindPFlag("delegator.key", ServeCmd.Flags().Lookup("delegator-key")))
	cobra.CheckErr(viper.BindPFlag("delegator.key_file", ServeCmd.Flags().Lookup("delegator-key-file")))
	cobra.CheckErr(viper.BindPFlag("delegator.did", ServeCmd.Flags().Lookup("delegator-did")))
	cobra.CheckErr(viper.BindPFlag("delegator.indexing_service_web_did", ServeCmd.Flags().Lookup("delegator-indexing-service-did")))
	cobra.CheckErr(viper.BindPFlag("delegator.indexing_service_proof", ServeCmd.Flags().Lookup("delegator-indexing-service-proof")))
	cobra.CheckErr(viper.BindPFlag("delegator.egress_tracking_service_did", ServeCmd.Flags().Lookup("delegator-egress-tracking-service-did")))
	cobra.CheckErr(viper.BindPFlag("delegator.egress_tracking_service_proof", ServeCmd.Flags().Lookup("delegator-egress-tracking-service-proof")))
	cobra.CheckErr(viper.BindPFlag("delegator.upload_service_did", ServeCmd.Flags().Lookup("delegator-upload-service-did")))
}
