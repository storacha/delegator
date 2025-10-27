package config

import (
	"fmt"

	"github.com/spf13/viper"
)

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
			Key:                        viper.GetString("delegator.key"),
			KeyFile:                    viper.GetString("delegator.key_file"),
			DID:                        viper.GetString("delegator.did"),
			IndexingServiceWebDID:      viper.GetString("delegator.indexing_service_web_did"),
			IndexingServiceProof:       viper.GetString("delegator.indexing_service_proof"),
			EgressTrackingServiceDID:   viper.GetString("delegator.egress_tracking_service_did"),
			EgressTrackingServiceProof: viper.GetString("delegator.egress_tracking_service_proof"),
			UploadServiceDID:           viper.GetString("delegator.upload_service_did"),
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

	if cfg.Delegator.Key == "" && cfg.Delegator.KeyFile == "" {
		return nil, fmt.Errorf("either delegator key or key file must be set")
	}
	if cfg.Delegator.Key != "" && cfg.Delegator.KeyFile != "" {
		return nil, fmt.Errorf("both delegator key and key file are set, please provide only one")
	}
	if cfg.Delegator.DID == "" {
		return nil, fmt.Errorf("delegator DID not set")
	}
	if cfg.Delegator.IndexingServiceWebDID == "" {
		return nil, fmt.Errorf("delegator indexing service DID not set")
	}
	if cfg.Delegator.IndexingServiceProof == "" {
		return nil, fmt.Errorf("delegator indexing service proof not set")
	}
	if cfg.Delegator.EgressTrackingServiceDID == "" {
		return nil, fmt.Errorf("delegator egress tracking service DID not set")
	}
	if cfg.Delegator.EgressTrackingServiceProof == "" {
		return nil, fmt.Errorf("delegator egress tracking service proof not set")
	}
	if cfg.Delegator.UploadServiceDID == "" {
		return nil, fmt.Errorf("delegator upload service DID not set")
	}

	return cfg, nil
}

type Config struct {
	Server    ServerConfig           `mapstructure:"server"`
	Store     DynamoConfig           `mapstructure:"store"`
	Delegator DelegatorServiceConfig `mapstructure:"delegator"`
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
	Key                        string `mapstructure:"key"`
	KeyFile                    string `mapstructure:"key_file"`
	DID                        string `mapstructure:"did"`
	IndexingServiceWebDID      string `mapstructure:"indexing_service_web_did"`
	IndexingServiceProof       string `mapstructure:"indexing_service_proof"`
	EgressTrackingServiceDID   string `mapstructure:"egress_tracking_service_did"`
	EgressTrackingServiceProof string `mapstructure:"egress_tracking_service_proof"`
	UploadServiceDID           string `mapstructure:"upload_service_did"`
}
