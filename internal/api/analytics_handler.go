package api

import (
	"net/http"
	"time"

	"edr-server/internal/models"
	"edr-server/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type AnalyticsHandler struct {
	analyticsService *services.AnalyticsService
}

func NewAnalyticsHandler(analyticsService *services.AnalyticsService) *AnalyticsHandler {
	return &AnalyticsHandler{
		analyticsService: analyticsService,
	}
}

// EventCorrelation correlates events to identify patterns
func (h *AnalyticsHandler) EventCorrelation(c *gin.Context) {
	filters := make(map[string]interface{})
	
	// Parse query parameters
	if agentID := c.Query("agent_id"); agentID != "" {
		filters["agent_id"] = agentID
	}
	if eventType := c.Query("event_type"); eventType != "" {
		filters["event_type"] = eventType
	}
	if timeRange := c.Query("time_range"); timeRange != "" {
		filters["time_range"] = timeRange
	}

	events, err := h.analyticsService.EventCorrelation(c.Request.Context(), filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"events": events})
}

// AnomalyDetection detects anomalous behavior patterns
func (h *AnalyticsHandler) AnomalyDetection(c *gin.Context) {
	agentID := c.Param("agentId")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Agent ID is required"})
		return
	}

	timeRangeStr := c.DefaultQuery("time_range", "24h")
	timeRange, err := time.ParseDuration(timeRangeStr)
	if err != nil {
		timeRange = 24 * time.Hour // Default to 24 hours
	}

	anomalies, err := h.analyticsService.AnomalyDetection(c.Request.Context(), agentID, timeRange)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"anomalies": anomalies})
}

// ThreatHunting performs advanced threat hunting queries
func (h *AnalyticsHandler) ThreatHunting(c *gin.Context) {
	var query models.ThreatHuntQuery
	if err := c.ShouldBindJSON(&query); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	results, err := h.analyticsService.ThreatHunting(c.Request.Context(), query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"results": results})
}

// GetDashboardMetrics returns metrics for dashboard
func (h *AnalyticsHandler) GetDashboardMetrics(c *gin.Context) {
	metrics, err := h.analyticsService.GetDashboardMetrics(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"metrics": metrics})
}

// GetPerformanceMetrics returns performance metrics
func (h *AnalyticsHandler) GetPerformanceMetrics(c *gin.Context) {
	timeRangeStr := c.DefaultQuery("time_range", "1h")
	timeRange, err := time.ParseDuration(timeRangeStr)
	if err != nil {
		timeRange = time.Hour // Default to 1 hour
	}

	metrics, err := h.analyticsService.GetPerformanceMetrics(c.Request.Context(), timeRange)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"metrics": metrics})
}

// GenerateReport generates comprehensive security report
func (h *AnalyticsHandler) GenerateReport(c *gin.Context) {
	reportType := c.Param("type")
	if reportType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Report type is required"})
		return
	}

	timeRangeStr := c.DefaultQuery("time_range", "24h")
	timeRange, err := time.ParseDuration(timeRangeStr)
	if err != nil {
		timeRange = 24 * time.Hour // Default to 24 hours
	}

	report, err := h.analyticsService.GenerateReport(c.Request.Context(), reportType, timeRange)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"report": report})
}

// GetAnomalyStats returns anomaly statistics
func (h *AnalyticsHandler) GetAnomalyStats(c *gin.Context) {
	// Get anomaly statistics from database
	var totalAnomalies int64
	var resolvedAnomalies int64
	var highSeverityAnomalies int64

	// This would typically query the database for anomaly statistics
	// For now, return mock data
	stats := gin.H{
		"total_anomalies":        totalAnomalies,
		"resolved_anomalies":     resolvedAnomalies,
		"high_severity":          highSeverityAnomalies,
		"detection_rate":         0.85,
		"false_positive_rate":    0.12,
		"average_resolution_time": "2.5h",
	}

	c.JSON(http.StatusOK, gin.H{"stats": stats})
}

// GetThreatHuntQueries returns saved threat hunting queries
func (h *AnalyticsHandler) GetThreatHuntQueries(c *gin.Context) {
	// This would typically query the database for saved queries
	// For now, return mock data
	queries := []models.ThreatHuntQuery{
		{
			ID:          uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
			Name:        "Suspicious Process Activity",
			Description: "Hunt for unusual process creation patterns",
			EventType:   "process_creation",
			TimeRange:   "24h",
			Status:      "active",
		},
		{
			ID:          uuid.MustParse("550e8400-e29b-41d4-a716-446655440001"),
			Name:        "Network Anomalies",
			Description: "Detect unusual network connections",
			EventType:   "network_connection",
			TimeRange:   "12h",
			Status:      "active",
		},
	}

	c.JSON(http.StatusOK, gin.H{"queries": queries})
}

// SaveThreatHuntQuery saves a new threat hunting query
func (h *AnalyticsHandler) SaveThreatHuntQuery(c *gin.Context) {
	var query models.ThreatHuntQuery
	if err := c.ShouldBindJSON(&query); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// This would typically save to database
	// For now, return success
	c.JSON(http.StatusOK, gin.H{"message": "Query saved successfully", "id": query.ID})
}

// GetReportHistory returns report generation history
func (h *AnalyticsHandler) GetReportHistory(c *gin.Context) {
	// This would typically query the database for report history
	// For now, return mock data
	reports := []models.SecurityReport{
		{
			ID:          uuid.MustParse("550e8400-e29b-41d4-a716-446655440002"),
			Type:        "threat_summary",
			Title:       "Daily Threat Summary",
			Description: "Daily summary of threat intelligence",
			GeneratedAt: time.Now().Add(-24 * time.Hour),
			Status:      "completed",
		},
		{
			ID:          uuid.MustParse("550e8400-e29b-41d4-a716-446655440003"),
			Type:        "comprehensive",
			Title:       "Weekly Security Report",
			Description: "Comprehensive weekly security analysis",
			GeneratedAt: time.Now().Add(-7 * 24 * time.Hour),
			Status:      "completed",
		},
	}

	c.JSON(http.StatusOK, gin.H{"reports": reports})
} 