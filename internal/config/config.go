package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the application
type Config struct {
	Server     ServerConfig     `mapstructure:"server"`
	Database   DatabaseConfig   `mapstructure:"database"`
	AWS        AWSConfig        `mapstructure:"aws"`
	Log        LogConfig        `mapstructure:"log"`
	Onboarding OnboardingConfig `mapstructure:"onboarding"`
	DynamoDB   DynamoDBConfig   `mapstructure:"dynamodb"`
}

// OnboardingConfig holds onboarding-specific configuration
type OnboardingConfig struct {
	SessionTimeout          time.Duration `mapstructure:"session_timeout"`
	DelegationTTL           time.Duration `mapstructure:"delegation_ttl"`
	FQDNVerificationTimeout time.Duration `mapstructure:"fqdn_verification_timeout"`
	MaxRetries              int           `mapstructure:"max_retries"`
	IndexingServiceKey      string        `mapstructure:"indexing_service_key"`
	UploadServiceKey        string        `mapstructure:"upload_service_key"`
	AllowedDIDs             []string      `mapstructure:"allowed_dids"`
	ServiceName             string        `mapstructure:"service_name"`
}

// DynamoDBConfig holds DynamoDB table configuration
type DynamoDBConfig struct {
	AllowlistTable    string `mapstructure:"allowlist_table"`
	SessionsTable     string `mapstructure:"sessions_table"`
	ProvidersTable    string `mapstructure:"providers_table"`
	ProviderInfoTable string `mapstructure:"provider_info_table"`
}

// ServerConfig holds server-specific configuration
type ServerConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	SessionKey   string        `mapstructure:"session_key"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Region    string `mapstructure:"region"`
	TableName string `mapstructure:"table_name"`
	Endpoint  string `mapstructure:"endpoint"`
}

// AWSConfig holds AWS-specific configuration
type AWSConfig struct {
	Region          string `mapstructure:"region"`
	AccessKeyID     string `mapstructure:"access_key_id"`
	SecretAccessKey string `mapstructure:"secret_access_key"`
	SessionToken    string `mapstructure:"session_token"`
}

// LogConfig holds logging configuration
type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

// New creates a new viper instance with proper defaults and search paths
func New() *viper.Viper {
	v := viper.New()

	// Set config file properties
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./configs")
	v.AddConfigPath("$HOME/.delegator")
	v.AddConfigPath("/etc/delegator")

	// Environment variable support
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.SetEnvPrefix("DELEGATOR")

	// Set defaults
	setDefaults(v)

	return v
}

// Load loads configuration using the provided viper instance
func Load(v *viper.Viper) (*Config, error) {
	// Read config file if it exists
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	if err := validate(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}

func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.host", "localhost")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.read_timeout", 30)
	v.SetDefault("server.write_timeout", 30)
	v.SetDefault("server.session_key", "storacha-delegator-secret-key")

	// Database defaults
	v.SetDefault("database.region", "us-west-2")
	v.SetDefault("database.table_name", "providers")

	// AWS defaults
	v.SetDefault("aws.region", "us-west-2")

	// Log defaults
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")

	// Onboarding defaults
	v.SetDefault("onboarding.session_timeout", 3600)
	v.SetDefault("onboarding.delegation_ttl", 86400)
	v.SetDefault("onboarding.fqdn_verification_timeout", 30)
	v.SetDefault("onboarding.max_retries", 3)
	v.SetDefault("onboarding.allowed_dids", []string{})
	v.SetDefault("onboarding.service_name", "Storacha")
	v.SetDefault("onboarding.help_text_settings", map[string]string{})

	// DynamoDB defaults
	v.SetDefault("dynamodb.allowlist_table", "allowed-dids")
	v.SetDefault("dynamodb.sessions_table", "onboarding-sessions")
	v.SetDefault("dynamodb.providers_table", "staging-warm-w3infra-storage-provider")
	v.SetDefault("dynamodb.provider_info_table", "staging-warm-w3infra-storage-provider-info")
}

func validate(config *Config) error {
	if config.Server.Port < 1 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", config.Server.Port)
	}

	return nil
}
