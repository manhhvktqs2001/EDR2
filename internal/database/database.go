package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"edr-server/internal/config"
	"edr-server/internal/models"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// InitPostgreSQL initializes PostgreSQL connection
func InitPostgreSQL(cfg config.PostgreSQLConfig) (*gorm.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s TimeZone=UTC",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Database, cfg.SSLMode,
	)

	// Configure GORM
	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Error), // Only log errors, not all SQL queries
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	}

	db, err := gorm.Open(postgres.Open(dsn), gormConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	// Get underlying sql.DB
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get sql.DB: %w", err)
	}

	// Configure connection pool
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetConnMaxLifetime(time.Duration(cfg.ConnMaxLifetime) * time.Second)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping PostgreSQL: %w", err)
	}

	// Enable UUID extension
	if err := db.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"").Error; err != nil {
		return nil, fmt.Errorf("failed to create uuid-ossp extension: %w", err)
	}

	// Auto migrate models
	if err := autoMigrate(db); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	// Create indexes
	if err := createIndexes(db); err != nil {
		return nil, fmt.Errorf("failed to create indexes: %w", err)
	}

	// Insert default data
	if err := insertDefaultData(db); err != nil {
		return nil, fmt.Errorf("failed to insert default data: %w", err)
	}

	return db, nil
}

// InitInfluxDB initializes InfluxDB connection
func InitInfluxDB(cfg config.InfluxDBConfig) (influxdb2.Client, error) {
	client := influxdb2.NewClient(cfg.URL, cfg.Token)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	health, err := client.Health(ctx)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to check InfluxDB health: %w", err)
	}

	if health.Status != "pass" {
		client.Close()
		return nil, fmt.Errorf("InfluxDB health check failed: status=%s, message=%s",
			health.Status, *health.Message)
	}

	// Verify bucket exists
	bucketsAPI := client.BucketsAPI()
	bucket, err := bucketsAPI.FindBucketByName(ctx, cfg.Bucket)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to find InfluxDB bucket: %w", err)
	}
	if bucket == nil {
		client.Close()
		return nil, fmt.Errorf("InfluxDB bucket '%s' not found", cfg.Bucket)
	}

	return client, nil
}

// InitRedis initializes Redis connection
func InitRedis(cfg config.RedisConfig) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         cfg.Address,
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		MaxRetries:   cfg.MaxRetries,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolTimeout:  4 * time.Second,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.Ping(ctx).Result()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to ping Redis: %w", err)
	}

	return client, nil
}

// InitMinIO initializes MinIO connection
func InitMinIO(cfg config.MinIOConfig) (*minio.Client, error) {
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create MinIO client: %w", err)
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Check if bucket exists
	exists, err := client.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("failed to check if MinIO bucket exists: %w", err)
	}

	// Create bucket if it doesn't exist
	if !exists {
		err = client.MakeBucket(ctx, cfg.Bucket, minio.MakeBucketOptions{
			Region: cfg.Region,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create MinIO bucket: %w", err)
		}

		// Set bucket policy to allow read access for certain objects
		policy := fmt.Sprintf(`{
			"Version": "2012-10-17",
			"Statement": [
				{
					"Effect": "Allow",
					"Principal": {"AWS": ["*"]},
					"Action": ["s3:GetObject"],
					"Resource": ["arn:aws:s3:::%s/public/*"]
				}
			]
		}`, cfg.Bucket)

		err = client.SetBucketPolicy(ctx, cfg.Bucket, policy)
		if err != nil {
			// Non-fatal error, continue
			fmt.Printf("Warning: failed to set MinIO bucket policy: %v\n", err)
		}
	}

	return client, nil
}

// autoMigrate runs database migrations
func autoMigrate(db *gorm.DB) error {
	// First, drop views that might interfere with migrations
	views := []string{
		"v_active_agents",
		"v_recent_alerts",
		"v_agent_stats",
		"v_alert_stats",
		"v_system_health",
	}

	for _, view := range views {
		db.Exec(fmt.Sprintf("DROP VIEW IF EXISTS %s CASCADE", view))
	}

	models := []interface{}{
		&models.Agent{},
		&models.YaraRule{},
		&models.RuleDeployment{},
		&models.Alert{},
		&models.AlertHistory{},
		&models.Whitelist{},
		&models.QuarantinedFile{},
		&models.ThreatIntelligence{},
		&models.AgentGroup{},
		&models.AgentTask{},
		&models.SystemConfig{},
		&models.NotificationSetting{},
		&models.AuditLog{},
	}

	for _, model := range models {
		if err := db.AutoMigrate(model); err != nil {
			// Log the error but continue - this allows the server to start even with migration issues
			fmt.Printf("Warning: failed to migrate %T: %v\n", model, err)
			// Don't return error for migration issues in development
			continue
		}
	}

	// Recreate views after migration
	if err := CreateViews(db); err != nil {
		fmt.Printf("Warning: failed to recreate views: %v\n", err)
	}

	return nil
}

// createIndexes creates additional database indexes for performance
func createIndexes(db *gorm.DB) error {
	indexes := []string{
		// Agents indexes
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_agents_hostname ON agents(hostname)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_agents_status_last_seen ON agents(status, last_seen DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_agents_os_type ON agents(os_type)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_agents_department ON agents(department)",

		// YARA Rules indexes
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_yara_rules_category_active ON yara_rules(category, is_active)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_yara_rules_platform ON yara_rules(platform)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_yara_rules_severity ON yara_rules(severity DESC)",

		// Alerts indexes
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_status_severity ON alerts(status, severity DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_detection_time ON alerts(detection_time DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_agent_status ON alerts(agent_id, status)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_file_hash ON alerts(file_hash) WHERE file_hash IS NOT NULL",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_process_name ON alerts(process_name) WHERE process_name IS NOT NULL",

		// Rule Deployments indexes
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_rule_deployments_status ON rule_deployments(status)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_rule_deployments_agent_status ON rule_deployments(agent_id, status)",

		// Agent Tasks indexes
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_agent_tasks_status_priority ON agent_tasks(status, priority DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_agent_tasks_created_at ON agent_tasks(created_at DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_agent_tasks_agent_status ON agent_tasks(agent_id, status)",

		// Threat Intelligence indexes
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_threat_intel_type_value ON threat_intelligence(indicator_type, indicator_value)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_threat_intel_active_severity ON threat_intelligence(is_active, severity DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_threat_intel_source ON threat_intelligence(source)",

		// Audit Logs indexes
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_action_timestamp ON audit_logs(action, timestamp DESC)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_user_timestamp ON audit_logs(user_id, timestamp DESC)",

		// Quarantined Files indexes
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_quarantined_files_status ON quarantined_files(status)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_quarantined_files_agent_status ON quarantined_files(agent_id, status)",

		// Whitelist indexes
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_whitelist_type_active ON whitelist(type, is_active)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_whitelist_expires_at ON whitelist(expires_at) WHERE expires_at IS NOT NULL",
	}

	for _, indexSQL := range indexes {
		if err := db.Exec(indexSQL).Error; err != nil {
			// Log warning but don't fail - index might already exist
			// Only log if it's not a "already exists" error
			if !strings.Contains(err.Error(), "already exists") && !strings.Contains(err.Error(), "duplicate key") {
				fmt.Printf("Warning: failed to create index: %v\n", err)
			}
		}
	}

	return nil
}

// insertDefaultData inserts initial system data
func insertDefaultData(db *gorm.DB) error {
	// Check if data already exists
	var count int64
	db.Model(&models.SystemConfig{}).Count(&count)
	if count > 0 {
		fmt.Println("✅ Default data already exists, skipping...")
		return nil // Data already exists
	}

	// Default system configuration
	defaultConfigs := []models.SystemConfig{
		{Category: "general", Key: "system_name", Value: "EDR System", Description: "Name of the EDR system"},
		{Category: "general", Key: "version", Value: "1.0.0", Description: "System version"},
		{Category: "general", Key: "retention_days", Value: "90", Description: "Data retention period in days", DataType: "integer"},
		{Category: "alerts", Key: "auto_resolve_days", Value: "30", Description: "Auto-resolve alerts after N days", DataType: "integer"},
		{Category: "agents", Key: "heartbeat_timeout", Value: "300", Description: "Agent heartbeat timeout in seconds", DataType: "integer"},
		{Category: "agents", Key: "default_heartbeat_interval", Value: "30", Description: "Default heartbeat interval", DataType: "integer"},
		{Category: "yara", Key: "max_rules_per_agent", Value: "1000", Description: "Maximum YARA rules per agent", DataType: "integer"},
		{Category: "notifications", Key: "email_enabled", Value: "false", Description: "Enable email notifications", DataType: "boolean"},
		{Category: "performance", Key: "cleanup_interval_hours", Value: "24", Description: "Database cleanup interval", DataType: "integer"},
		{Category: "security", Key: "max_login_attempts", Value: "5", Description: "Maximum login attempts", DataType: "integer"},
		{Category: "security", Key: "session_timeout", Value: "3600", Description: "Session timeout in seconds", DataType: "integer"},
	}

	for _, config := range defaultConfigs {
		if err := db.Create(&config).Error; err != nil {
			return fmt.Errorf("failed to create default config: %w", err)
		}
	}

	// Default agent groups
	defaultGroups := []models.AgentGroup{
		{
			ID:          uuid.New(),
			Name:        "Default",
			Description: "Default group for all agents",
			GroupType:   "default",
			Config:      models.JSONB{"auto_assign": true},
		},
		{
			ID:          uuid.New(),
			Name:        "Windows Servers",
			Description: "Windows server machines",
			GroupType:   "custom",
			Rules:       models.JSONB{"os_type": "Windows", "tags": []string{"server"}},
		},
		{
			ID:          uuid.New(),
			Name:        "Linux Workstations",
			Description: "Linux desktop machines",
			GroupType:   "custom",
			Rules:       models.JSONB{"os_type": "Linux", "tags": []string{"workstation"}},
		},
	}

	for _, group := range defaultGroups {
		if err := db.Create(&group).Error; err != nil {
			return fmt.Errorf("failed to create default group: %w", err)
		}
	}

	// Sample threat intelligence
	defaultThreatIntel := []models.ThreatIntelligence{
		{
			ID:             uuid.New(),
			IndicatorType:  "hash",
			IndicatorValue: "44d88612fea8a8f36de82e1278abb02f",
			ThreatType:     "malware",
			Confidence:     &[]int{90}[0],
			Source:         "Internal",
			Description:    "Known malicious file hash",
			Severity:       4,
			IsActive:       true,
		},
		{
			ID:             uuid.New(),
			IndicatorType:  "domain",
			IndicatorValue: "malicious-site.com",
			ThreatType:     "c2",
			Confidence:     &[]int{85}[0],
			Source:         "Threat Feed",
			Description:    "Command and control server",
			Severity:       5,
			IsActive:       true,
		},
		{
			ID:             uuid.New(),
			IndicatorType:  "ip",
			IndicatorValue: "192.0.2.100",
			ThreatType:     "scanner",
			Confidence:     &[]int{70}[0],
			Source:         "Internal",
			Description:    "Suspicious scanning activity",
			Severity:       3,
			IsActive:       true,
		},
	}

	for _, intel := range defaultThreatIntel {
		if err := db.Create(&intel).Error; err != nil {
			return fmt.Errorf("failed to create default threat intel: %w", err)
		}
	}

	// Sample YARA rules
	defaultYaraRules := []models.YaraRule{
		{
			ID:          uuid.New(),
			Name:        "Suspicious_PE",
			Content:     `rule Suspicious_PE { meta: description = "Detects suspicious PE files" author = "EDR Team" severity = 3 condition: uint16(0) == 0x5A4D and filesize < 10MB }`,
			Description: "Basic PE file detection rule",
			Author:      "EDR Team",
			Severity:    3,
			Category:    "malware",
			Platform:    "Windows",
			IsActive:    true,
		},
		{
			ID:          uuid.New(),
			Name:        "Network_Scanner",
			Content:     `rule Network_Scanner { meta: description = "Detects network scanning tools" author = "EDR Team" severity = 4 strings: $nmap = "nmap" nocase $masscan = "masscan" nocase condition: any of them }`,
			Description: "Detects common network scanning tools",
			Author:      "EDR Team",
			Severity:    4,
			Category:    "network",
			Platform:    "All",
			IsActive:    true,
		},
	}

	for _, rule := range defaultYaraRules {
		if err := db.Create(&rule).Error; err != nil {
			return fmt.Errorf("failed to create default YARA rule: %w", err)
		}
	}

	return nil
}

// CreateTriggers creates database triggers for automatic updates
func CreateTriggers(db *gorm.DB) error {
	// Function to update timestamp
	updateFunction := `
	CREATE OR REPLACE FUNCTION update_updated_at_column()
	RETURNS TRIGGER AS $
	BEGIN
		NEW.updated_at = NOW();
		RETURN NEW;
	END;
	$ language 'plpgsql';`

	if err := db.Exec(updateFunction).Error; err != nil {
		return fmt.Errorf("failed to create update function: %w", err)
	}

	// Tables that need updated_at triggers
	tables := []string{
		"agents", "yara_rules", "alerts", "whitelist",
		"threat_intelligence", "agent_groups", "notification_settings",
	}

	for _, table := range tables {
		triggerSQL := fmt.Sprintf(`
		DROP TRIGGER IF EXISTS update_%s_updated_at ON %s;
		CREATE TRIGGER update_%s_updated_at 
		BEFORE UPDATE ON %s 
		FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();`,
			table, table, table, table)

		if err := db.Exec(triggerSQL).Error; err != nil {
			return fmt.Errorf("failed to create trigger for %s: %w", table, err)
		}
	}

	return nil
}

// CreateViews creates database views for dashboard queries
func CreateViews(db *gorm.DB) error {
	views := []string{
		// Active Agents View
		`CREATE OR REPLACE VIEW v_active_agents AS
		SELECT 
			a.*,
			CASE 
				WHEN a.last_seen > NOW() - INTERVAL '5 minutes' THEN 'online'
				WHEN a.last_seen > NOW() - INTERVAL '1 hour' THEN 'warning'
				ELSE 'offline'
			END as real_status,
			EXTRACT(EPOCH FROM (NOW() - a.last_seen))::INTEGER as seconds_since_last_seen
		FROM agents a`,

		// Recent Alerts View
		`CREATE OR REPLACE VIEW v_recent_alerts AS
		SELECT 
			al.*,
			ag.hostname,
			ag.ip_address,
			yr.name as rule_name,
			yr.category as rule_category
		FROM alerts al
		JOIN agents ag ON al.agent_id = ag.id
		LEFT JOIN yara_rules yr ON al.rule_id = yr.id
		WHERE al.created_at > NOW() - INTERVAL '24 hours'
		ORDER BY al.created_at DESC`,

		// Agent Statistics View
		`CREATE OR REPLACE VIEW v_agent_stats AS
		SELECT 
			os_type,
			status,
			COUNT(*) as count,
			AVG(EXTRACT(EPOCH FROM (NOW() - last_seen))) as avg_last_seen_seconds
		FROM agents 
		GROUP BY os_type, status`,

		// Alert Statistics View
		`CREATE OR REPLACE VIEW v_alert_stats AS
		SELECT 
			DATE(created_at) as alert_date,
			severity,
			status,
			COUNT(*) as count
		FROM alerts 
		WHERE created_at > NOW() - INTERVAL '30 days'
		GROUP BY DATE(created_at), severity, status
		ORDER BY alert_date DESC`,
	}

	for _, viewSQL := range views {
		if err := db.Exec(viewSQL).Error; err != nil {
			return fmt.Errorf("failed to create view: %w", err)
		}
	}

	return nil
}

// HealthCheck performs a comprehensive health check of all databases
func HealthCheck(db *gorm.DB, influxClient influxdb2.Client, redisClient *redis.Client, minioClient *minio.Client) map[string]interface{} {
	health := make(map[string]interface{})
	ctx := context.Background()

	// PostgreSQL health
	sqlDB, err := db.DB()
	if err != nil {
		health["postgresql"] = map[string]interface{}{"status": "error", "error": err.Error()}
	} else {
		err = sqlDB.Ping()
		if err != nil {
			health["postgresql"] = map[string]interface{}{"status": "error", "error": err.Error()}
		} else {
			stats := sqlDB.Stats()
			health["postgresql"] = map[string]interface{}{
				"status":           "healthy",
				"open_connections": stats.OpenConnections,
				"in_use":           stats.InUse,
				"idle":             stats.Idle,
			}
		}
	}

	// InfluxDB health
	healthResult, err := influxClient.Health(ctx)
	if err != nil {
		health["influxdb"] = map[string]interface{}{"status": "error", "error": err.Error()}
	} else {
		health["influxdb"] = map[string]interface{}{
			"status":  healthResult.Status,
			"message": healthResult.Message,
		}
	}

	// Redis health
	_, err = redisClient.Ping(ctx).Result()
	if err != nil {
		health["redis"] = map[string]interface{}{"status": "error", "error": err.Error()}
	} else {
		info := redisClient.Info(ctx, "memory").Val()
		health["redis"] = map[string]interface{}{
			"status": "healthy",
			"info":   info,
		}
	}

	// MinIO health
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err = minioClient.ListBuckets(ctx)
	if err != nil {
		health["minio"] = map[string]interface{}{"status": "error", "error": err.Error()}
	} else {
		health["minio"] = map[string]interface{}{"status": "healthy"}
	}

	return health
}
