package api

import (
	"net/http"
	"strconv"

	"edr-server/internal/services"
	"edr-server/internal/websocket"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type AlertHandler struct {
	alertService *services.AlertService
	wsHub        *websocket.Hub
}

func NewAlertHandler(alertService *services.AlertService, wsHub *websocket.Hub) *AlertHandler {
	return &AlertHandler{
		alertService: alertService,
		wsHub:        wsHub,
	}
}

// List returns list of alerts
func (h *AlertHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	status := c.Query("status")
	severity := c.Query("severity")
	agentID := c.Query("agent_id")

	alerts, total, err := h.alertService.ListAlerts(page, limit, status, severity, agentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"alerts": alerts,
		"total":  total,
		"page":   page,
		"limit":  limit,
	})
}

// Get returns a single alert
func (h *AlertHandler) Get(c *gin.Context) {
	alertID := c.Param("id")
	id, err := uuid.Parse(alertID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid alert_id"})
		return
	}

	alert, err := h.alertService.GetAlert(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "alert not found"})
		return
	}

	c.JSON(http.StatusOK, alert)
}

// Update updates an alert
func (h *AlertHandler) Update(c *gin.Context) {
	alertID := c.Param("id")
	id, err := uuid.Parse(alertID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid alert_id"})
		return
	}

	var req struct {
		Status       string `json:"status"`
		AnalystNotes string `json:"analyst_notes"`
		ChangedBy    string `json:"changed_by"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updates := map[string]interface{}{
		"status":        req.Status,
		"analyst_notes": req.AnalystNotes,
	}
	err = h.alertService.UpdateAlert(id, updates)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Broadcast alert update
	h.wsHub.Broadcast("alert_updated", map[string]interface{}{
		"alert_id":      id,
		"status":        req.Status,
		"analyst_notes": req.AnalystNotes,
	})

	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// Delete deletes an alert
func (h *AlertHandler) Delete(c *gin.Context) {
	alertID := c.Param("id")
	id, err := uuid.Parse(alertID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid alert_id"})
		return
	}

	err = h.alertService.DeleteAlert(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// Resolve marks an alert as resolved
func (h *AlertHandler) Resolve(c *gin.Context) {
	alertID := c.Param("id")
	id, err := uuid.Parse(alertID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid alert_id"})
		return
	}

	var req struct {
		Resolution string `json:"resolution"`
		ChangedBy  string `json:"changed_by"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err = h.alertService.ResolveAlert(id, req.Resolution)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Broadcast alert resolution
	h.wsHub.Broadcast("alert_resolved", map[string]interface{}{
		"alert_id":   id,
		"resolution": req.Resolution,
	})

	c.JSON(http.StatusOK, gin.H{"status": "resolved"})
}

// MarkFalsePositive marks an alert as false positive
func (h *AlertHandler) MarkFalsePositive(c *gin.Context) {
	alertID := c.Param("id")
	id, err := uuid.Parse(alertID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid alert_id"})
		return
	}

	var req struct {
		Reason    string `json:"reason"`
		ChangedBy string `json:"changed_by"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err = h.alertService.MarkFalsePositive(id, req.Reason)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "marked_false_positive"})
}

// GetStats returns alert statistics
func (h *AlertHandler) GetStats(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "30"))

	stats, err := h.alertService.GetAlertStats(days)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// GetTimeline returns alert timeline
func (h *AlertHandler) GetTimeline(c *gin.Context) {
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))

	timeline, err := h.alertService.GetAlertTimeline(hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, timeline)
}
