package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Storage  StorageConfig  `mapstructure:"storage"`
	Security SecurityConfig `mapstructure:"security"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	Features FeatureConfig  `mapstructure:"features"`
}

type ServerConfig struct {
	Address     string `mapstructure:"address"`
	Mode        string `mapstructure:"mode"`
	TLSEnabled  bool   `mapstructure:"tls_enabled"`
	CertFile    string `mapstructure:"cert_file"`
	KeyFile     string `mapstructure:"key_file"`
	MaxRequests int    `mapstructure:"max_requests"`
}

type DatabaseConfig struct {
	PostgreSQL PostgreSQLConfig `mapstructure:"postgresql"`
	InfluxDB   InfluxDBConfig   `mapstructure:"influxdb"`
	Redis      RedisConfig      `mapstructure:"redis"`
}

type PostgreSQLConfig struct {
	Host            string `mapstructure:"host"`
	Port            int    `mapstructure:"port"`
	User            string `mapstructure:"user"`
	Password        string `mapstructure:"password"`
	Database        string `mapstructure:"database"`
	SSLMode         string `mapstructure:"sslmode"`
	MaxIdleConns    int    `mapstructure:"max_idle_conns"`
	MaxOpenConns    int    `mapstructure:"max_open_conns"`
	ConnMaxLifetime int    `mapstructure:"conn_max_lifetime"`
}

type InfluxDBConfig struct {
	URL           string `mapstructure:"url"`
	Token         string `mapstructure:"token"`
	Org           string `mapstructure:"org"`
	Bucket        string `mapstructure:"bucket"`
	RetentionDays int    `mapstructure:"retention_days"`
	BatchSize     int    `mapstructure:"batch_size"`
}

type RedisConfig struct {
	Address      string `mapstructure:"address"`
	Password     string `mapstructure:"password"`
	DB           int    `mapstructure:"db"`
	PoolSize     int    `mapstructure:"pool_size"`
	MinIdleConns int    `mapstructure:"min_idle_conns"`
	MaxRetries   int    `mapstructure:"max_retries"`
}

type StorageConfig struct {
	MinIO MinIOConfig `mapstructure:"minio"`
}

type MinIOConfig struct {
	Endpoint       string   `mapstructure:"endpoint"`
	AccessKey      string   `mapstructure:"access_key"`
	SecretKey      string   `mapstructure:"secret_key"`
	UseSSL         bool     `mapstructure:"use_ssl"`
	Bucket         string   `mapstructure:"bucket"`
	Region         string   `mapstructure:"region"`
	MaxFileSize    int64    `mapstructure:"max_file_size"`
	AllowedFormats []string `mapstructure:"allowed_formats"`
}

type SecurityConfig struct {
	JWTSecret      string   `mapstructure:"jwt_secret"`
	EncryptKey     string   `mapstructure:"encrypt_key"`
	APIKeyAuth     bool     `mapstructure:"api_key_auth"`
	RateLimit      int      `mapstructure:"rate_limit"`
	AllowedOrigins []string `mapstructure:"allowed_origins"`
	TrustedProxies []string `mapstructure:"trusted_proxies"`
}

type LoggingConfig struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	Output     string `mapstructure:"output"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"`
}

type FeatureConfig struct {
	AutoQuarantine    bool `mapstructure:"auto_quarantine"`
	RealTimeScanning  bool `mapstructure:"realtime_scanning"`
	ThreatIntel       bool `mapstructure:"threat_intel"`
	MachineLearning   bool `mapstructure:"machine_learning"`
	NetworkMonitoring bool `mapstructure:"network_monitoring"`
	FileIntegrity     bool `mapstructure:"file_integrity"`
}

func Load() (*Config, error) {
	viper.SetConfigName("app")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath("/etc/edr")
	viper.AddConfigPath("$HOME/.edr")

	// Environment variables
	viper.AutomaticEnv()
	viper.SetEnvPrefix("EDR")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Set default values
	setDefaults()

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found, use defaults and environment variables
		fmt.Println("⚠️  Config file not found, using defaults and environment variables")
	} else {
		fmt.Printf("✅ Using config file: %s\n", viper.ConfigFileUsed())
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

func setDefaults() {
	// Server defaults
	viper.SetDefault("server.address", ":5000")
	viper.SetDefault("server.mode", "debug")
	viper.SetDefault("server.tls_enabled", false)
	viper.SetDefault("server.max_requests", 1000)

	// Database defaults
	viper.SetDefault("database.postgresql.host", "localhost")
	viper.SetDefault("database.postgresql.port", 5432)
	viper.SetDefault("database.postgresql.user", "edr_user")
	viper.SetDefault("database.postgresql.password", "edr_password")
	viper.SetDefault("database.postgresql.database", "edr_db")
	viper.SetDefault("database.postgresql.sslmode", "disable")
	viper.SetDefault("database.postgresql.max_idle_conns", 10)
	viper.SetDefault("database.postgresql.max_open_conns", 100)
	viper.SetDefault("database.postgresql.conn_max_lifetime", 3600)

	// InfluxDB defaults
	viper.SetDefault("database.influxdb.url", "http://localhost:8086")
	viper.SetDefault("database.influxdb.token", "")
	viper.SetDefault("database.influxdb.org", "edr-org")
	viper.SetDefault("database.influxdb.bucket", "events")
	viper.SetDefault("database.influxdb.retention_days", 30)
	viper.SetDefault("database.influxdb.batch_size", 1000)

	viper.SetDefault("database.redis.address", "localhost:6379")
	viper.SetDefault("database.redis.db", 0)
	viper.SetDefault("database.redis.pool_size", 10)
	viper.SetDefault("database.redis.min_idle_conns", 5)
	viper.SetDefault("database.redis.max_retries", 3)

	// Storage defaults
	viper.SetDefault("storage.minio.endpoint", "localhost:9000")
	viper.SetDefault("storage.minio.bucket", "edr-files")
	viper.SetDefault("storage.minio.use_ssl", false)
	viper.SetDefault("storage.minio.region", "us-east-1")
	viper.SetDefault("storage.minio.max_file_size", 100*1024*1024) // 100MB
	viper.SetDefault("storage.minio.allowed_formats", []string{".yar", ".yara", ".exe", ".dll", ".bin"})

	// Security defaults
	viper.SetDefault("security.jwt_secret", generateRandomSecret())
	viper.SetDefault("security.encrypt_key", generateRandomSecret())
	viper.SetDefault("security.api_key_auth", false)
	viper.SetDefault("security.rate_limit", 100)
	viper.SetDefault("security.allowed_origins", []string{"*"})

	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("logging.output", "stdout")
	viper.SetDefault("logging.max_size", 100)
	viper.SetDefault("logging.max_backups", 3)
	viper.SetDefault("logging.max_age", 28)

	// Feature defaults
	viper.SetDefault("features.auto_quarantine", true)
	viper.SetDefault("features.realtime_scanning", true)
	viper.SetDefault("features.threat_intel", true)
	viper.SetDefault("features.machine_learning", false)
	viper.SetDefault("features.network_monitoring", true)
	viper.SetDefault("features.file_integrity", true)
}

func validateConfig(config *Config) error {
	// Validate server config
	if config.Server.Address == "" {
		return fmt.Errorf("server address cannot be empty")
	}

	if config.Server.Mode != "debug" && config.Server.Mode != "release" && config.Server.Mode != "production" {
		return fmt.Errorf("invalid server mode: %s", config.Server.Mode)
	}

	// Validate database config
	if config.Database.PostgreSQL.Host == "" {
		return fmt.Errorf("PostgreSQL host cannot be empty")
	}

	if config.Database.PostgreSQL.Port < 1 || config.Database.PostgreSQL.Port > 65535 {
		return fmt.Errorf("invalid PostgreSQL port: %d", config.Database.PostgreSQL.Port)
	}

	if config.Database.InfluxDB.URL == "" {
		return fmt.Errorf("InfluxDB URL cannot be empty")
	}

	if config.Database.Redis.Address == "" {
		return fmt.Errorf("Redis address cannot be empty")
	}

	// Validate storage config
	if config.Storage.MinIO.Endpoint == "" {
		return fmt.Errorf("MinIO endpoint cannot be empty")
	}

	if config.Storage.MinIO.Bucket == "" {
		return fmt.Errorf("MinIO bucket cannot be empty")
	}

	// Validate security config
	if len(config.Security.JWTSecret) < 32 {
		return fmt.Errorf("JWT secret must be at least 32 characters long")
	}

	if len(config.Security.EncryptKey) < 32 {
		return fmt.Errorf("encryption key must be at least 32 characters long")
	}

	// Validate logging config
	validLogLevels := []string{"debug", "info", "warn", "error", "fatal"}
	validLevel := false
	for _, level := range validLogLevels {
		if config.Logging.Level == level {
			validLevel = true
			break
		}
	}
	if !validLevel {
		return fmt.Errorf("invalid log level: %s", config.Logging.Level)
	}

	return nil
}

func generateRandomSecret() string {
	// In production, you should use a proper random generator
	// This is just for development
	return "default-secret-key-change-in-production"
}

// SaveConfig saves the current configuration to file
func SaveConfig(config *Config, filename string) error {
	viper.SetConfigFile(filename)

	// Set all values in viper
	viper.Set("server", config.Server)
	viper.Set("database", config.Database)
	viper.Set("storage", config.Storage)
	viper.Set("security", config.Security)
	viper.Set("logging", config.Logging)
	viper.Set("features", config.Features)

	return viper.WriteConfig()
}

// GetConfigTemplate returns a template configuration for initial setup
func GetConfigTemplate() *Config {
	return &Config{
		Server: ServerConfig{
			Address:     ":5000",
			Mode:        "debug",
			TLSEnabled:  false,
			MaxRequests: 1000,
		},
		Database: DatabaseConfig{
			PostgreSQL: PostgreSQLConfig{
				Host:            "localhost",
				Port:            5432,
				User:            "edr_user",
				Password:        "edr_password",
				Database:        "edr_db",
				SSLMode:         "disable",
				MaxIdleConns:    10,
				MaxOpenConns:    100,
				ConnMaxLifetime: 3600,
			},
			InfluxDB: InfluxDBConfig{
				URL:           "http://localhost:8086",
				Org:           "edr-org",
				Bucket:        "events",
				RetentionDays: 30,
				BatchSize:     1000,
			},
			Redis: RedisConfig{
				Address:      "localhost:6379",
				DB:           0,
				PoolSize:     10,
				MinIdleConns: 5,
				MaxRetries:   3,
			},
		},
		Storage: StorageConfig{
			MinIO: MinIOConfig{
				Endpoint:       "localhost:9000",
				Bucket:         "edr-files",
				UseSSL:         false,
				Region:         "us-east-1",
				MaxFileSize:    100 * 1024 * 1024,
				AllowedFormats: []string{".yar", ".yara", ".exe", ".dll", ".bin"},
			},
		},
		Security: SecurityConfig{
			APIKeyAuth:     false,
			RateLimit:      100,
			AllowedOrigins: []string{"*"},
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "json",
			Output:     "stdout",
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     28,
		},
		Features: FeatureConfig{
			AutoQuarantine:    true,
			RealTimeScanning:  true,
			ThreatIntel:       true,
			MachineLearning:   false,
			NetworkMonitoring: true,
			FileIntegrity:     true,
		},
	}
}

// LoadFromEnv loads configuration from environment variables only
func LoadFromEnv() (*Config, error) {
	viper.AutomaticEnv()
	viper.SetEnvPrefix("EDR")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	setDefaults()

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config from env: %w", err)
	}

	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration from env: %w", err)
	}

	return &config, nil
}

// PrintConfig prints the current configuration (with sensitive data masked)
func PrintConfig(config *Config) {
	fmt.Println("📋 Current Configuration:")
	fmt.Printf("   Server: %s (mode: %s)\n", config.Server.Address, config.Server.Mode)
	fmt.Printf("   PostgreSQL: %s:%d/%s\n", config.Database.PostgreSQL.Host,
		config.Database.PostgreSQL.Port, config.Database.PostgreSQL.Database)
	fmt.Printf("   InfluxDB: %s/%s\n", config.Database.InfluxDB.URL, config.Database.InfluxDB.Bucket)
	fmt.Printf("   Redis: %s (DB: %d)\n", config.Database.Redis.Address, config.Database.Redis.DB)
	fmt.Printf("   MinIO: %s/%s\n", config.Storage.MinIO.Endpoint, config.Storage.MinIO.Bucket)
	fmt.Printf("   Features: AutoQuarantine=%v, RealTimeScanning=%v, ThreatIntel=%v\n",
		config.Features.AutoQuarantine, config.Features.RealTimeScanning, config.Features.ThreatIntel)
}
