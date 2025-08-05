package api

import (
	"net/http"
	"strconv"

	"edr-server/internal/services"

	"github.com/gin-gonic/gin"
)

type DashboardHandler struct {
	agentService *services.AgentService
	alertService *services.AlertService
	eventService *services.EventService
}

func NewDashboardHandler(agentService *services.AgentService, alertService *services.AlertService, eventService *services.EventService) *DashboardHandler {
	return &DashboardHandler{
		agentService: agentService,
		alertService: alertService,
		eventService: eventService,
	}
}

// GetOverview returns system overview
func (h *DashboardHandler) GetOverview(c *gin.Context) {
	overview, err := h.agentService.GetSystemOverview()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, overview)
}

// GetMetrics returns system metrics
func (h *DashboardHandler) GetMetrics(c *gin.Context) {
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))

	metrics, err := h.agentService.GetSystemMetrics(hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, metrics)
}

// GetRecentAlerts returns recent alerts
func (h *DashboardHandler) GetRecentAlerts(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))

	alerts, err := h.alertService.GetRecentAlerts(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"alerts": alerts})
}

// GetAgentStatus returns agent status summary
func (h *DashboardHandler) GetAgentStatus(c *gin.Context) {
	status, err := h.agentService.GetAgentStatusSummary()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, status)
}

// GetThreatTrends returns threat trends
func (h *DashboardHandler) GetThreatTrends(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "30"))

	trends, err := h.alertService.GetThreatTrends(days)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, trends)
}

// GetPerformance returns performance metrics
func (h *DashboardHandler) GetPerformance(c *gin.Context) {
	performance, err := h.eventService.GetPerformanceMetrics()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, performance)
}
