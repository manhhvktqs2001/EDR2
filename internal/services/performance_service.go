package services

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"edr-server/internal/models"

	"github.com/go-redis/redis/v8"
	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"gorm.io/gorm"
)

type PerformanceService struct {
	db       *gorm.DB
	influxDB influxdb2.Client
	redis    *redis.Client
	org      string
	bucket   string
}

func NewPerformanceService(db *gorm.DB, influxDB influxdb2.Client, redis *redis.Client) *PerformanceService {
	return &PerformanceService{
		db:       db,
		influxDB: influxDB,
		redis:    redis,
		org:      "edr-org",
		bucket:   "events",
	}
}

// BatchEventIngest processes events in batches for better performance
func (s *PerformanceService) BatchEventIngest(ctx context.Context, events []models.Event) error {
	if len(events) == 0 {
		return nil
	}

	// Batch size for optimal performance
	batchSize := 1000
	batches := (len(events) + batchSize - 1) / batchSize

	for i := 0; i < batches; i++ {
		start := i * batchSize
		end := start + batchSize
		if end > len(events) {
			end = len(events)
		}

		batch := events[start:end]
		if err := s.processEventBatch(ctx, batch); err != nil {
			return fmt.Errorf("failed to process batch %d: %w", i, err)
		}
	}

	return nil
}

// processEventBatch processes a batch of events
func (s *PerformanceService) processEventBatch(ctx context.Context, events []models.Event) error {
	// Write to InfluxDB in batch
	writeAPI := s.influxDB.WriteAPIBlocking(s.org, s.bucket)

	for _, event := range events {
		point := influxdb2.NewPoint(
			"security_events",
			map[string]string{
				"agent_id":   event.AgentID,
				"event_type": event.EventType,
			},
			map[string]interface{}{
				"timestamp": event.Timestamp.Unix(),
				"data":      event.Data,
			},
			event.Timestamp,
		)
		writeAPI.WritePoint(ctx, point)
	}

	return writeAPI.Flush(ctx)
}

// QueryOptimization optimizes database queries
func (s *PerformanceService) QueryOptimization(ctx context.Context) error {
	// Create indexes for frequently queried columns
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_alerts_agent_id ON alerts(agent_id)",
		"CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)",
		"CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at)",
		"CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status)",
		"CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen)",
		"CREATE INDEX IF NOT EXISTS idx_threat_intel_indicator ON threat_intelligence(indicator_type, indicator_value)",
		"CREATE INDEX IF NOT EXISTS idx_threat_intel_severity ON threat_intelligence(severity)",
	}

	for _, index := range indexes {
		if err := s.db.Exec(index).Error; err != nil {
			log.Printf("Warning: Failed to create index: %v", err)
		}
	}

	return nil
}

// Monitoring provides system monitoring capabilities
func (s *PerformanceService) Monitoring(ctx context.Context) (*models.SystemMetrics, error) {
	metrics := &models.SystemMetrics{
		Timestamp: time.Now(),
	}

	// Database metrics
	var alertCount, agentCount, eventCount int64
	s.db.Model(&models.Alert{}).Count(&alertCount)
	s.db.Model(&models.Agent{}).Count(&agentCount)

	// InfluxDB event count
	query := `
		from(bucket: "events")
		|> range(start: -1h)
		|> filter(fn: (r) => r["_measurement"] == "security_events")
		|> count()
	`

	queryAPI := s.influxDB.QueryAPI(s.org)
	result, err := queryAPI.Query(ctx, query)
	if err == nil {
		if result.Next() {
			eventCount = result.Record().Value().(int64)
		}
		result.Close()
	}

	metrics.DatabaseMetrics = models.DatabaseMetrics{
		AlertCount: alertCount,
		AgentCount: agentCount,
		EventCount: eventCount,
	}

	// Performance metrics
	metrics.PerformanceMetrics = s.getPerformanceMetrics(ctx)

	// System health
	metrics.SystemHealth = s.getSystemHealth(ctx)

	return metrics, nil
}

// getPerformanceMetrics gets performance metrics
func (s *PerformanceService) getPerformanceMetrics(ctx context.Context) models.PerformanceMetrics {
	metrics := models.PerformanceMetrics{
		Timestamp: time.Now(),
	}

	// Query performance data from InfluxDB
	query := `
		from(bucket: "events")
		|> range(start: -1h)
		|> filter(fn: (r) => r["_measurement"] == "performance")
		|> group(columns: ["agent_id"])
		|> mean()
	`

	queryAPI := s.influxDB.QueryAPI(s.org)
	result, err := queryAPI.Query(ctx, query)
	if err == nil {
		for result.Next() {
			agentID := result.Record().ValueByKey("agent_id").(string)
			cpuUsage := result.Record().ValueByKey("cpu_usage").(float64)
			memoryUsage := result.Record().ValueByKey("memory_usage").(float64)

			metrics.AgentPerformance[agentID] = models.AgentPerformance{
				CPUUsage:    cpuUsage,
				MemoryUsage: memoryUsage,
			}
		}
		result.Close()
	}

	return metrics
}

// getSystemHealth gets system health status
func (s *PerformanceService) getSystemHealth(ctx context.Context) models.SystemHealth {
	health := models.SystemHealth{
		Timestamp: time.Now(),
		Status:    "healthy",
	}

	// Check database connectivity
	if err := s.db.Raw("SELECT 1").Error; err != nil {
		health.Status = "degraded"
		health.DatabaseStatus = "error"
	} else {
		health.DatabaseStatus = "healthy"
	}

	// Check Redis connectivity
	if err := s.redis.Ping(ctx).Err(); err != nil {
		health.Status = "degraded"
		health.RedisStatus = "error"
	} else {
		health.RedisStatus = "healthy"
	}

	// Check InfluxDB connectivity
	queryAPI := s.influxDB.QueryAPI(s.org)
	_, err := queryAPI.Query(ctx, "from(bucket: \"events\") |> range(start: -1m) |> limit(n:1)")
	if err != nil {
		health.Status = "degraded"
		health.InfluxDBStatus = "error"
	} else {
		health.InfluxDBStatus = "healthy"
	}

	return health
}

// LogRotation manages log file rotation
func (s *PerformanceService) LogRotation(ctx context.Context) error {
	logDir := "logs"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Rotate log files
	logFiles := []string{"edr-server.log", "access.log", "error.log"}

	for _, logFile := range logFiles {
		if err := s.rotateLogFile(logDir, logFile); err != nil {
			log.Printf("Warning: Failed to rotate log file %s: %v", logFile, err)
		}
	}

	return nil
}

// rotateLogFile rotates a single log file
func (s *PerformanceService) rotateLogFile(logDir, filename string) error {
	logPath := filepath.Join(logDir, filename)

	// Check if file exists and is larger than 10MB
	info, err := os.Stat(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist, nothing to rotate
		}
		return err
	}

	// Rotate if file is larger than 10MB
	if info.Size() > 10*1024*1024 {
		// Create backup filename with timestamp
		backupName := fmt.Sprintf("%s.%s", filename, time.Now().Format("2006-01-02-15-04-05"))
		backupPath := filepath.Join(logDir, backupName)

		// Move current file to backup
		if err := os.Rename(logPath, backupPath); err != nil {
			return fmt.Errorf("failed to rotate log file: %w", err)
		}

		// Create new empty log file
		if _, err := os.Create(logPath); err != nil {
			return fmt.Errorf("failed to create new log file: %w", err)
		}

		log.Printf("Rotated log file: %s -> %s", filename, backupName)
	}

	return nil
}

// RetentionPolicy manages data retention policies
func (s *PerformanceService) RetentionPolicy(ctx context.Context) error {
	// Clean up old alerts (keep for 90 days)
	alertRetention := time.Now().AddDate(0, 0, -90)
	if err := s.db.Where("created_at < ?", alertRetention).Delete(&models.Alert{}).Error; err != nil {
		log.Printf("Warning: Failed to clean up old alerts: %v", err)
	}

	// Clean up old audit logs (keep for 30 days)
	auditRetention := time.Now().AddDate(0, 0, -30)
	if err := s.db.Where("timestamp < ?", auditRetention).Delete(&models.AuditLog{}).Error; err != nil {
		log.Printf("Warning: Failed to clean up old audit logs: %v", err)
	}

	// Clean up old threat intelligence (keep for 180 days)
	tiRetention := time.Now().AddDate(0, 0, -180)
	if err := s.db.Where("created_at < ?", tiRetention).Delete(&models.ThreatIntelligence{}).Error; err != nil {
		log.Printf("Warning: Failed to clean up old threat intelligence: %v", err)
	}

	// Clean up old events from InfluxDB (keep for 30 days)
	eventRetention := time.Now().AddDate(0, 0, -30)

	// Use InfluxDB delete API instead of Flux query
	deleteAPI := s.influxDB.DeleteAPI()
	err := deleteAPI.DeleteWithName(ctx, s.org, s.bucket, eventRetention, time.Now(), "")
	if err != nil {
		log.Printf("Warning: Failed to clean up old events: %v", err)
	} else {
		log.Printf("Info: Successfully cleaned up events older than %s", eventRetention.Format("2006-01-02"))
	}

	return nil
}

// GetSystemMetrics returns comprehensive system metrics
func (s *PerformanceService) GetSystemMetrics(ctx context.Context) (*models.SystemMetrics, error) {
	metrics := &models.SystemMetrics{
		Timestamp: time.Now(),
	}

	// Database metrics
	var alertCount, agentCount, tiCount int64
	s.db.Model(&models.Alert{}).Count(&alertCount)
	s.db.Model(&models.Agent{}).Count(&agentCount)
	s.db.Model(&models.ThreatIntelligence{}).Count(&tiCount)

	metrics.DatabaseMetrics = models.DatabaseMetrics{
		AlertCount: alertCount,
		AgentCount: agentCount,
		EventCount: 0, // Will be filled from InfluxDB
	}

	// Get event count from InfluxDB
	query := `
		from(bucket: "events")
		|> range(start: -1h)
		|> filter(fn: (r) => r["_measurement"] == "security_events")
		|> count()
	`

	queryAPI := s.influxDB.QueryAPI(s.org)
	result, err := queryAPI.Query(ctx, query)
	if err == nil {
		if result.Next() {
			metrics.DatabaseMetrics.EventCount = result.Record().Value().(int64)
		}
		result.Close()
	}

	// Performance metrics
	metrics.PerformanceMetrics = s.getPerformanceMetrics(ctx)

	// System health
	metrics.SystemHealth = s.getSystemHealth(ctx)

	return metrics, nil
}

// OptimizeQueries optimizes database queries for better performance
func (s *PerformanceService) OptimizeQueries(ctx context.Context) error {
	// Set GORM configuration for better performance
	s.db = s.db.Session(&gorm.Session{
		PrepareStmt: true, // Enable prepared statements
		DryRun:      false,
	})

	// Set connection pool settings
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}

	// Configure connection pool
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	return nil
}

// StartMonitoring starts continuous monitoring
func (s *PerformanceService) StartMonitoring(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.LogRotation(ctx); err != nil {
				log.Printf("Error during log rotation: %v", err)
			}

			if err := s.RetentionPolicy(ctx); err != nil {
				log.Printf("Error during retention policy: %v", err)
			}

			// Log system metrics
			metrics, err := s.Monitoring(ctx)
			if err != nil {
				log.Printf("Error getting system metrics: %v", err)
			} else {
				log.Printf("System Metrics - Alerts: %d, Agents: %d, Events: %d, Status: %s",
					metrics.DatabaseMetrics.AlertCount,
					metrics.DatabaseMetrics.AgentCount,
					metrics.DatabaseMetrics.EventCount,
					metrics.SystemHealth.Status)
			}
		}
	}
}
