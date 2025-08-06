package services

import (
	"context"
	"fmt"
	"time"

	"edr-server/internal/models"

	"github.com/go-redis/redis/v8"
	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"gorm.io/gorm"
)

type AnalyticsService struct {
	db       *gorm.DB
	influxDB influxdb2.Client
	redis    *redis.Client
	org      string
	bucket   string
}

func NewAnalyticsService(db *gorm.DB, influxDB influxdb2.Client, redis *redis.Client) *AnalyticsService {
	return &AnalyticsService{
		db:       db,
		influxDB: influxDB,
		redis:    redis,
		org:      "edr-org",
		bucket:   "events",
	}
}

// EventCorrelation correlates events to identify patterns
func (s *AnalyticsService) EventCorrelation(ctx context.Context, filters map[string]interface{}) ([]models.Event, error) {
	query := `
		from(bucket: "events")
		|> range(start: -1h)
		|> filter(fn: (r) => r["_measurement"] == "security_events")
		|> group(columns: ["agent_id", "event_type"])
		|> count()
		|> filter(fn: (r) => r["_value"] > 5)
	`

	queryAPI := s.influxDB.QueryAPI(s.org)
	result, err := queryAPI.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}
	defer result.Close()

	var events []models.Event
	for result.Next() {
		event := models.Event{
			AgentID:   result.Record().ValueByKey("agent_id").(string),
			EventType: result.Record().ValueByKey("event_type").(string),
			Timestamp: result.Record().Time(),
			Data:      make(map[string]interface{}),
		}
		events = append(events, event)
	}

	return events, nil
}

// AnomalyDetection detects anomalous behavior patterns
func (s *AnalyticsService) AnomalyDetection(ctx context.Context, agentID string, timeRange time.Duration) ([]models.Anomaly, error) {
	// Query for unusual patterns
	query := fmt.Sprintf(`
		from(bucket: "events")
		|> range(start: -%dh)
		|> filter(fn: (r) => r["agent_id"] == "%s")
		|> group(columns: ["event_type", "process_name"])
		|> count()
		|> filter(fn: (r) => r["_value"] > 10)
	`, int(timeRange.Hours()), agentID)

	queryAPI := s.influxDB.QueryAPI(s.org)
	result, err := queryAPI.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to detect anomalies: %w", err)
	}
	defer result.Close()

	var anomalies []models.Anomaly
	for result.Next() {
		anomaly := models.Anomaly{
			AgentID:     agentID,
			Type:        "high_frequency",
			EventType:   result.Record().ValueByKey("event_type").(string),
			ProcessName: result.Record().ValueByKey("process_name").(string),
			Count:       int(result.Record().Value().(int64)),
			Severity:    "medium",
			DetectedAt:  time.Now(),
		}
		anomalies = append(anomalies, anomaly)
	}

	return anomalies, nil
}

// ThreatHunting performs advanced threat hunting queries
func (s *AnalyticsService) ThreatHunting(ctx context.Context, query models.ThreatHuntQuery) ([]models.ThreatHuntResult, error) {
	// Build InfluxDB query based on hunt parameters
	fluxQuery := s.buildThreatHuntQuery(query)

	queryAPI := s.influxDB.QueryAPI(s.org)
	result, err := queryAPI.Query(ctx, fluxQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to execute threat hunt: %w", err)
	}
	defer result.Close()

	var results []models.ThreatHuntResult
	for result.Next() {
		huntResult := models.ThreatHuntResult{
			QueryID:    query.ID,
			AgentID:    result.Record().ValueByKey("agent_id").(string),
			EventType:  result.Record().ValueByKey("event_type").(string),
			Timestamp:  result.Record().Time(),
			Confidence: 0.8,
			Data:       make(map[string]interface{}),
		}
		results = append(results, huntResult)
	}

	return results, nil
}

// buildThreatHuntQuery builds InfluxDB query for threat hunting
func (s *AnalyticsService) buildThreatHuntQuery(query models.ThreatHuntQuery) string {
	baseQuery := `
		from(bucket: "events")
		|> range(start: -24h)
		|> filter(fn: (r) => r["_measurement"] == "security_events")
	`

	if query.AgentID != "" {
		baseQuery += fmt.Sprintf(`|> filter(fn: (r) => r["agent_id"] == "%s")`, query.AgentID)
	}

	if query.EventType != "" {
		baseQuery += fmt.Sprintf(`|> filter(fn: (r) => r["event_type"] == "%s")`, query.EventType)
	}

	if query.ProcessName != "" {
		baseQuery += fmt.Sprintf(`|> filter(fn: (r) => r["process_name"] == "%s")`, query.ProcessName)
	}

	return baseQuery
}

// GetDashboardMetrics returns metrics for dashboard
func (s *AnalyticsService) GetDashboardMetrics(ctx context.Context) (*models.DashboardMetrics, error) {
	metrics := &models.DashboardMetrics{
		Timestamp: time.Now(),
	}

	// Get agent statistics
	var agentCount int64
	s.db.Model(&models.Agent{}).Count(&agentCount)
	metrics.AgentCount = int(agentCount)

	// Get alert statistics
	var alertCount int64
	s.db.Model(&models.Alert{}).Where("status = ?", "new").Count(&alertCount)
	metrics.NewAlerts = int(alertCount)

	// Get event statistics from InfluxDB
	eventQuery := `
		from(bucket: "events")
		|> range(start: -1h)
		|> filter(fn: (r) => r["_measurement"] == "security_events")
		|> count()
	`

	queryAPI := s.influxDB.QueryAPI(s.org)
	result, err := queryAPI.Query(ctx, eventQuery)
	if err == nil {
		if result.Next() {
			metrics.EventsPerHour = int(result.Record().Value().(int64))
		}
		result.Close()
	}

	// Get threat intelligence statistics
	var tiCount int64
	s.db.Model(&models.ThreatIntelligence{}).Where("is_active = ?", true).Count(&tiCount)
	metrics.ActiveThreats = int(tiCount)

	return metrics, nil
}

// GetPerformanceMetrics returns performance metrics
func (s *AnalyticsService) GetPerformanceMetrics(ctx context.Context, timeRange time.Duration) (*models.PerformanceMetrics, error) {
	metrics := &models.PerformanceMetrics{
		Timestamp: time.Now(),
		TimeRange: timeRange,
	}

	// Query performance data from InfluxDB
	query := fmt.Sprintf(`
		from(bucket: "events")
		|> range(start: -%dh)
		|> filter(fn: (r) => r["_measurement"] == "performance")
		|> group(columns: ["agent_id"])
		|> mean()
	`, int(timeRange.Hours()))

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

	return metrics, nil
}

// GenerateReport generates comprehensive security report
func (s *AnalyticsService) GenerateReport(ctx context.Context, reportType string, timeRange time.Duration) (*models.SecurityReport, error) {
	report := &models.SecurityReport{
		Type:        reportType,
		GeneratedAt: time.Now(),
		TimeRange:   timeRange,
	}

	switch reportType {
	case "threat_summary":
		report.Data = s.generateThreatSummary(ctx, timeRange)
	case "agent_activity":
		report.Data = s.generateAgentActivityReport(ctx, timeRange)
	case "alert_analysis":
		report.Data = s.generateAlertAnalysis(ctx, timeRange)
	case "comprehensive":
		report.Data = s.generateComprehensiveReport(ctx, timeRange)
	}

	return report, nil
}

// generateThreatSummary generates threat summary report
func (s *AnalyticsService) generateThreatSummary(ctx context.Context, timeRange time.Duration) map[string]interface{} {
	summary := make(map[string]interface{})

	// Get threat intelligence summary
	var threats []models.ThreatIntelligence
	s.db.Where("is_active = ?", true).Find(&threats)

	summary["total_threats"] = len(threats)
	summary["high_severity"] = 0
	summary["medium_severity"] = 0
	summary["low_severity"] = 0

	for _, threat := range threats {
		switch threat.Severity {
		case 4, 5:
			summary["high_severity"] = summary["high_severity"].(int) + 1
		case 3:
			summary["medium_severity"] = summary["medium_severity"].(int) + 1
		default:
			summary["low_severity"] = summary["low_severity"].(int) + 1
		}
	}

	return summary
}

// generateAgentActivityReport generates agent activity report
func (s *AnalyticsService) generateAgentActivityReport(ctx context.Context, timeRange time.Duration) map[string]interface{} {
	activity := make(map[string]interface{})

	// Get agent statistics
	var agents []models.Agent
	s.db.Find(&agents)

	onlineCount := 0
	offlineCount := 0

	for _, agent := range agents {
		if agent.IsOnline() {
			onlineCount++
		} else {
			offlineCount++
		}
	}

	activity["total_agents"] = len(agents)
	activity["online_agents"] = onlineCount
	activity["offline_agents"] = offlineCount
	activity["online_percentage"] = float64(onlineCount) / float64(len(agents)) * 100

	return activity
}

// generateAlertAnalysis generates alert analysis report
func (s *AnalyticsService) generateAlertAnalysis(ctx context.Context, timeRange time.Duration) map[string]interface{} {
	analysis := make(map[string]interface{})

	// Get alert statistics
	var alerts []models.Alert
	s.db.Where("created_at >= ?", time.Now().Add(-timeRange)).Find(&alerts)

	analysis["total_alerts"] = len(alerts)
	analysis["new_alerts"] = 0
	analysis["resolved_alerts"] = 0
	analysis["false_positives"] = 0

	for _, alert := range alerts {
		switch alert.Status {
		case "new":
			analysis["new_alerts"] = analysis["new_alerts"].(int) + 1
		case "resolved":
			analysis["resolved_alerts"] = analysis["resolved_alerts"].(int) + 1
		case "false_positive":
			analysis["false_positives"] = analysis["false_positives"].(int) + 1
		}
	}

	return analysis
}

// generateComprehensiveReport generates comprehensive security report
func (s *AnalyticsService) generateComprehensiveReport(ctx context.Context, timeRange time.Duration) map[string]interface{} {
	comprehensive := make(map[string]interface{})

	// Include all report types
	comprehensive["threat_summary"] = s.generateThreatSummary(ctx, timeRange)
	comprehensive["agent_activity"] = s.generateAgentActivityReport(ctx, timeRange)
	comprehensive["alert_analysis"] = s.generateAlertAnalysis(ctx, timeRange)

	// Add additional metrics
	comprehensive["report_generated_at"] = time.Now()
	comprehensive["time_range"] = timeRange.String()

	return comprehensive
}
