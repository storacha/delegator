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
	Long:  `Start the delegator HTTP server with configured endpoints.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.NewConfig()
		if err != nil {
			return err
		}
		app := fx.New(
			// Configuration
			config.SupplyConfig(cfg),
			fx.Provide(
				// Providers for complex types
				providers.ProvideSigner,
				providers.ProvideIndexingServiceWebDID,
				providers.ProvideIndexingServiceProof,
				providers.ProvideEgressTrackingServiceDID,
				providers.ProvideEgressTrackingServiceProof,
				providers.ProvideUploadServiceDID,
				providers.ProviderContractOperator,

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

const (
	FilecoinCalibrationNetworkChainID       = 314159
	FilecoinCalibrationNetworkChainEndpoint = "https://api.calibration.node.glif.io/rpc/v1"
)

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
	ServeCmd.Flags().String("delegator-key-file", "", "Path to delegator private key file")
	ServeCmd.Flags().String("delegator-indexing-service-did", "", "DID of the indexing service")
	ServeCmd.Flags().String("delegator-indexing-service-proof", "", "Path to proof file from indexing service")
	ServeCmd.Flags().String("delegator-egress-tracking-service-did", "", "DID of the egress tracking service")
	ServeCmd.Flags().String("delegator-egress-tracking-service-proof", "", "Path to proof file from egress tracking service")
	ServeCmd.Flags().String("delegator-upload-service-did", "", "DID of the upload service")

	// Contract operator flags
	ServeCmd.Flags().String("contract-chain-client-endpoint", FilecoinCalibrationNetworkChainEndpoint, "Blockchain client RPC endpoint URL")
	ServeCmd.Flags().String("contract-payments-contract-address", "", "Ethereum address of the payments contract")
	ServeCmd.Flags().String("contract-service-contract-address", "", "Ethereum address of the service contract")
	ServeCmd.Flags().String("contract-registry-contract-address", "", "Ethereum address of the registry contract")
	ServeCmd.Flags().Int64("contract-transactor-chain-id", FilecoinCalibrationNetworkChainID, "Chain ID for blockchain transactions")
	ServeCmd.Flags().String("contract-transactor-keystore-path", "", "Path to Ethereum keystore file for transaction signing")
	ServeCmd.Flags().String("contract-transactor-keystore-password", "", "Password for the Ethereum keystore file")

	// Bind flags to viper
	cobra.CheckErr(viper.BindPFlag("server.host", ServeCmd.Flags().Lookup("host")))
	cobra.CheckErr(viper.BindPFlag("server.port", ServeCmd.Flags().Lookup("port")))

	cobra.CheckErr(viper.BindPFlag("store.region", ServeCmd.Flags().Lookup("store-region")))
	cobra.CheckErr(viper.BindPFlag("store.allowlist_table_name", ServeCmd.Flags().Lookup("store-allowlist-table")))
	cobra.CheckErr(viper.BindPFlag("store.providerinfo_table_name", ServeCmd.Flags().Lookup("store-providerinfo-table")))
	cobra.CheckErr(viper.BindPFlag("store.providerweight", ServeCmd.Flags().Lookup("store-provider-weight")))
	cobra.CheckErr(viper.BindPFlag("store.endpoint", ServeCmd.Flags().Lookup("store-endpoint")))

	cobra.CheckErr(viper.BindPFlag("delegator.key_file", ServeCmd.Flags().Lookup("delegator-key-file")))
	cobra.CheckErr(viper.BindPFlag("delegator.indexing_service_web_did", ServeCmd.Flags().Lookup("delegator-indexing-service-did")))
	cobra.CheckErr(viper.BindPFlag("delegator.indexing_service_proof", ServeCmd.Flags().Lookup("delegator-indexing-service-proof")))
	cobra.CheckErr(viper.BindPFlag("delegator.egress_tracking_service_did", ServeCmd.Flags().Lookup("delegator-egress-tracking-service-did")))
	cobra.CheckErr(viper.BindPFlag("delegator.egress_tracking_service_proof", ServeCmd.Flags().Lookup("delegator-egress-tracking-service-proof")))
	cobra.CheckErr(viper.BindPFlag("delegator.upload_service_did", ServeCmd.Flags().Lookup("delegator-upload-service-did")))

	cobra.CheckErr(viper.BindPFlag("contract.chain_client_endpoint", ServeCmd.Flags().Lookup("contract-chain-client-endpoint")))
	cobra.CheckErr(viper.BindPFlag("contract.payments_contract_address", ServeCmd.Flags().Lookup("contract-payments-contract-address")))
	cobra.CheckErr(viper.BindPFlag("contract.service_contract_address", ServeCmd.Flags().Lookup("contract-service-contract-address")))
	cobra.CheckErr(viper.BindPFlag("contract.registry_contract_address", ServeCmd.Flags().Lookup("contract-registry-contract-address")))
	cobra.CheckErr(viper.BindPFlag("contract.transactor.chain_id", ServeCmd.Flags().Lookup("contract-transactor-chain-id")))
	cobra.CheckErr(viper.BindPFlag("contract.transactor.keystore_path", ServeCmd.Flags().Lookup("contract-transactor-keystore-path")))
	cobra.CheckErr(viper.BindPFlag("contract.transactor.keystore_password", ServeCmd.Flags().Lookup("contract-transactor-keystore-password")))
}
