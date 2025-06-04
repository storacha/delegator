package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/spf13/viper"
)

// Config holds all configuration for the application
type Config struct {
	Server     ServerConfig     `mapstructure:"server"`
	Onboarding OnboardingConfig `mapstructure:"onboarding"`
	Log        LogConfig        `mapstructure:"log"`
	Dynamo     DynamoConfig     `mapstructure:"dynamo"`
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
	// SessionTimeout is the duration a session will remain active for
	SessionTimeout time.Duration `mapstructure:"session_timeout"`

	// FQDNVerificationTimeout is the duration we'll wait when dialing the operators domain
	FQDNVerificationTimeout time.Duration `mapstructure:"fqdn_verification_timeout"`

	// AllowList is a list of DID's that are allowed to register. DID's may also be placed in to the AllowListTable of dynamo
	// Note: setting this value will cause a write to the dynamo table AllowListTableName when application starts.
	AllowList []string `mapstructure:"allow_list"`

	// The UploadServiceDID used for instruction to operator when creating a delegation for the upload to storage node.
	UploadServiceDID string `mapstructure:"upload_service_did"`

	// KeyFilePath is a path to a .pem file containing the private key of the delegator.
	KeyFilePath string `mapstructure:"key_file_path"`

	// IndexingServiceProof is a Base64-encoded CIDv1 string containing a proof from the indexing service
	// to the delegator allowing it to issue delegations to the storage node on its behalf for `claim/cache`.
	IndexingServiceProof string `mapstructure:"indexing_service_proof"`
}

// LogConfig holds logging configuration
type LogConfig struct {
	// Level is a log level, one of: debug, info, warn, error
	Level string `mapstructure:"level"`
}

type DynamoConfig struct {
	// Region of the dynamoDB instance
	Region string `mapstructure:"region"`
	// Name of table we use for allowing users to register
	AllowListTableName string `mapstructure:"allow_list_table_name"`
	// Name of table we persist registered user data to
	ProviderInfoTableName string `mapstructure:"provider_info_table_name"`

	// Endpoint may be set for local testing, usually with docker, e.g.
	// docker run -p 8000:8000 amazon/dynamodb-local -jar DynamoDBLocal.jar -sharedDb
	// then set endpoint to localhost:8080
	// Do not set for production.
	Endpoint string `mapstructure:"endpoint"` // for development
}

// New creates a new viper instance with proper defaults and search paths
func New() *viper.Viper {
	v := viper.New()

	// Set config file properties
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	// directories to look for a config file in
	v.AddConfigPath(".")
	v.AddConfigPath("./configs")
	v.AddConfigPath("$HOME/.delegator")
	v.AddConfigPath("/etc/delegator")

	// Environment variable support
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	// prefix of env vars
	v.SetEnvPrefix("STORACHA_DELEGATOR")

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

var Default = Config{
	Server: ServerConfig{
		Host:         "0.0.0.0",
		Port:         8080,
		ReadTimeout:  time.Minute,
		WriteTimeout: time.Minute,
		SessionKey:   "storacha-delegator-secret-key",
	},
	Onboarding: OnboardingConfig{
		SessionTimeout:          12 * time.Hour,
		FQDNVerificationTimeout: time.Minute,
		AllowList:               []string{}, // usually empty, candidates may be manually added to the AllowListTableName table
		UploadServiceDID:        "",         // required config
		IndexingServiceProof:    "",         // required config
		KeyFilePath:             "",         // required config
	},
	Log: LogConfig{
		Level: "info",
	},
	Dynamo: DynamoConfig{
		Region:                "", // required config
		AllowListTableName:    "", // required config
		ProviderInfoTableName: "", // required config
		Endpoint:              "", // only used in testing
	},
}

func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.host", Default.Server.Host)
	v.SetDefault("server.port", Default.Server.Port)
	v.SetDefault("server.read_timeout", Default.Server.ReadTimeout)
	v.SetDefault("server.write_timeout", Default.Server.WriteTimeout)
	v.SetDefault("server.session_key", Default.Server.SessionKey)

	// Log defaults
	v.SetDefault("log.level", Default.Log.Level)

	// Onboarding defaults
	v.SetDefault("onboarding.session_timeout", Default.Onboarding.SessionTimeout)
	v.SetDefault("onboarding.fqdn_verification_timeout", Default.Onboarding.FQDNVerificationTimeout)
	v.SetDefault("onboarding.indexing_service_proof", Default.Onboarding.IndexingServiceProof)
	v.SetDefault("onboarding.key_file_path", Default.Onboarding.KeyFilePath)
	v.SetDefault("onboarding.allow_list", Default.Onboarding.AllowList)

	// Dynamo defaults
	v.SetDefault("dynamo.region", Default.Dynamo.Region)
	v.SetDefault("dynamo.allow_list_table_name", Default.Dynamo.Endpoint)
	v.SetDefault("dynamo.provider_info_table_name", Default.Dynamo.Endpoint)
	v.SetDefault("dynamo.endpoint", Default.Dynamo.Endpoint)
}

func validate(config *Config) error {
	// return a multierror in the event many validations fail
	var errs error
	// Validate server config
	if config.Server.Port < 1 || config.Server.Port > 65535 {
		errs = multierror.Append(errs, fmt.Errorf("invalid server port: %d", config.Server.Port))
	}

	if config.Server.SessionKey == "" {
		errs = multierror.Append(errs, fmt.Errorf("server.session_key is required"))
	}
	if len(config.Server.SessionKey) != 32 {
		errs = multierror.Append(errs, fmt.Errorf("server.session_key must be 32 bytes long"))
	}

	// Validate onboarding config
	if config.Onboarding.IndexingServiceProof == "" {
		errs = multierror.Append(errs, fmt.Errorf("onboarding.indexing_service_proof is required"))
	}

	if config.Onboarding.KeyFilePath == "" {
		errs = multierror.Append(errs, fmt.Errorf("onboarding.key_file_path is required"))
	}

	if config.Onboarding.UploadServiceDID == "" {
		errs = multierror.Append(errs, fmt.Errorf("onboarding.upload_service_did is required"))
	}

	// Validate log config
	validLogLevels := []string{"debug", "info", "warn", "error"}
	isValidLogLevel := false
	for _, level := range validLogLevels {
		if strings.ToLower(config.Log.Level) == level {
			isValidLogLevel = true
			break
		}
	}
	if !isValidLogLevel {
		errs = multierror.Append(errs, fmt.Errorf("invalid log level: %s, must be one of: debug, info, warn, error", config.Log.Level))
	}

	// Validate dynamo config
	if config.Dynamo.Region == "" {
		errs = multierror.Append(errs, fmt.Errorf("dynamo.region is required"))
	}

	if config.Dynamo.AllowListTableName == "" {
		errs = multierror.Append(errs, fmt.Errorf("dynamo.allow_list_table_name is required"))
	}

	if config.Dynamo.ProviderInfoTableName == "" {
		errs = multierror.Append(errs, fmt.Errorf("dynamo.provider_info_table_name is required"))
	}

	return errs
}
