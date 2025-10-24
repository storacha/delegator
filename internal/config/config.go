package config

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/viper"
	"go.uber.org/fx"
)

func SupplyConfig(cfg *Config) fx.Option {
	return fx.Supply(
		cfg,
		cfg.Server,
		cfg.Store,
		cfg.Delegator,
		cfg.Contract,
		cfg.Contract.Transactor,
	)
}

func NewConfig() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Host: viper.GetString("server.host"),
			Port: viper.GetInt("server.port"),
		},
		Store: DynamoConfig{
			Region:                viper.GetString("store.region"),
			AllowListTableName:    viper.GetString("store.allowlist_table_name"),
			ProviderInfoTableName: viper.GetString("store.providerinfo_table_name"),
			ProviderWeight:        viper.GetUint("store.providerweight"),
			Endpoint:              viper.GetString("store.endpoint"),
		},
		Delegator: DelegatorServiceConfig{
			KeyFile:                    viper.GetString("delegator.key_file"),
			IndexingServiceWebDID:      viper.GetString("delegator.indexing_service_web_did"),
			IndexingServiceProof:       viper.GetString("delegator.indexing_service_proof"),
			EgressTrackingServiceDID:   viper.GetString("delegator.egress_tracking_service_did"),
			EgressTrackingServiceProof: viper.GetString("delegator.egress_tracking_service_proof"),
			UploadServiceDID:           viper.GetString("delegator.upload_service_did"),
		},
		Contract: ContractOperatorConfig{
			ChainClientEndpoint:     viper.GetString("contract.chain_client_endpoint"),
			PaymentsContractAddress: viper.GetString("contract.payments_contract_address"),
			ServiceContractAddress:  viper.GetString("contract.service_contract_address"),
			RegistryContractAddress: viper.GetString("contract.registry_contract_address"),
			Transactor: ContractTransactorConfig{
				ChainID:          viper.GetInt64("contract.transactor.chain_id"),
				KeystorePath:     viper.GetString("contract.transactor.keystore_path"),
				KeystorePassword: viper.GetString("contract.transactor.keystore_password"),
			},
		},
	}

	if cfg.Server.Host == "" {
		cfg.Server.Host = "0.0.0.0"
	}
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8080
	}

	if cfg.Store.Region == "" {
		return nil, fmt.Errorf("store region not set")
	}
	if cfg.Store.AllowListTableName == "" {
		return nil, fmt.Errorf("store allow list table not set")
	}
	if cfg.Store.ProviderInfoTableName == "" {
		return nil, fmt.Errorf("store provider info table not set")
	}

	if cfg.Delegator.KeyFile == "" {
		return nil, fmt.Errorf("delegator key file not set")
	}
	if cfg.Delegator.IndexingServiceWebDID == "" {
		return nil, fmt.Errorf("delegator indexing service did not set")
	}
	if cfg.Delegator.IndexingServiceProof == "" {
		return nil, fmt.Errorf("delegator indexing service proof not set")
	}
	if cfg.Delegator.EgressTrackingServiceDID == "" {
		return nil, fmt.Errorf("delegator egress tracking service did not set")
	}
	if cfg.Delegator.EgressTrackingServiceProof == "" {
		return nil, fmt.Errorf("delegator egress tracking service proof not set")
	}
	if cfg.Delegator.UploadServiceDID == "" {
		return nil, fmt.Errorf("delegator upload did not set")
	}

	if !common.IsHexAddress(cfg.Contract.RegistryContractAddress) {
		return nil, fmt.Errorf("registry contract address not set")
	}
	if !common.IsHexAddress(cfg.Contract.PaymentsContractAddress) {
		return nil, fmt.Errorf("payments contract address not set")
	}
	if !common.IsHexAddress(cfg.Contract.ServiceContractAddress) {
		return nil, fmt.Errorf("service contract address not set")
	}
	if cfg.Contract.ChainClientEndpoint == "" {
		return nil, fmt.Errorf("chain client endpoint not set")
	}
	// TODO we can have stronger validation here, there are only two allowed values
	// the filecoin mainnet and calibnet ID
	if cfg.Contract.Transactor.ChainID == 0 {
		return nil, fmt.Errorf("chain client id not set")
	}
	// decision on doing this will be made here: https://www.notion.so/storacha/Storacha-Forge-Contract-Billing-Operations-Design-Questions-28b5305b552480d08ea7c8a1ff077a2d?source=copy_link#28f5305b5524801e95e9f556ca7d8a9e
	// TODO this is really insecure, we may want to import the aws secret manager sdk and use directly
	if cfg.Contract.Transactor.KeystorePath == "" {
		return nil, fmt.Errorf("transactor keystore path not set")
	}
	// TODO this is really insecure, we may want to import the aws secret manager sdk and use directly
	if cfg.Contract.Transactor.KeystorePassword == "" {
		return nil, fmt.Errorf("transactor keystore password not set")
	}
	return cfg, nil
}

type Config struct {
	Server    ServerConfig           `mapstructure:"server"`
	Store     DynamoConfig           `mapstructure:"store"`
	Delegator DelegatorServiceConfig `mapstructure:"delegator"`
	Contract  ContractOperatorConfig `mapstructure:"contract"`
}
type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

func (c *ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

type DynamoConfig struct {
	// Region of the dynamoDB instance
	Region string `mapstructure:"region"`
	// Name of table we use for allowing users to register
	AllowListTableName string `mapstructure:"allowlist_table_name"`
	// Name of table we persist registered user data to
	ProviderInfoTableName string `mapstructure:"providerinfo_table_name"`

	// ProviderWeight is the weight that will be assigned to a provider
	// when they are registered. This value will affect their odds of being
	// selected for an upload. `0` means they will not be selected.
	ProviderWeight uint `mapstructure:"providerweight"`

	// Endpoint may be set for local testing, usually with docker, e.g.
	// docker run -p 8000:8000 amazon/dynamodb-local -jar DynamoDBLocal.jar -sharedDb
	// then set endpoint to localhost:8080
	// Do not set for production.
	Endpoint string `mapstructure:"endpoint"` // for development
}

type DelegatorServiceConfig struct {
	KeyFile                    string `mapstructure:"key_file"`
	IndexingServiceWebDID      string `mapstructure:"indexing_service_web_did"`
	IndexingServiceProof       string `mapstructure:"indexing_service_proof"`
	EgressTrackingServiceDID   string `mapstructure:"egress_tracking_service_did"`
	EgressTrackingServiceProof string `mapstructure:"egress_tracking_service_proof"`
	UploadServiceDID           string `mapstructure:"upload_service_did"`
}

type ContractOperatorConfig struct {
	ChainClientEndpoint     string                   `mapstructure:"chain_client_endpoint"`
	PaymentsContractAddress string                   `mapstructure:"payments_contract_address"`
	ServiceContractAddress  string                   `mapstructure:"service_contract_address"`
	RegistryContractAddress string                   `mapstructure:"registry_contract_address"`
	Transactor              ContractTransactorConfig `mapstructure:"transactor"`
}

type ContractTransactorConfig struct {
	ChainID          int64  `mapstructure:"chain_id"`
	KeystorePath     string `mapstructure:"keystore_path"`
	KeystorePassword string `mapstructure:"keystore_password"`
}
