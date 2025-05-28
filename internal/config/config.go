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
	Onboarding OnboardingConfig `mapstructure:"onboarding"`
	Log        LogConfig        `mapstructure:"log"`
}

// ServerConfig holds server-specific configuration
type ServerConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	SessionKey   string        `mapstructure:"session_key"`
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

// LogConfig holds logging configuration
type LogConfig struct {
	Level string `mapstructure:"level"`
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

	// Log defaults
	v.SetDefault("log.level", "info")

	// Onboarding defaults
	v.SetDefault("onboarding.session_timeout", 3600)
	v.SetDefault("onboarding.delegation_ttl", 86400)
	v.SetDefault("onboarding.fqdn_verification_timeout", 30)
	v.SetDefault("onboarding.max_retries", 3)
	v.SetDefault("onboarding.allowed_dids", []string{})
	v.SetDefault("onboarding.service_name", "Storacha")
}

func validate(config *Config) error {
	if config.Server.Port < 1 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", config.Server.Port)
	}

	return nil
}
