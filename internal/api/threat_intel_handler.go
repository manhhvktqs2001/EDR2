package api

import (
	"net/http"
	"strconv"

	"edr-server/internal/models"
	"edr-server/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type ThreatIntelHandler struct {
	threatIntelService *services.ThreatIntelService
}

func NewThreatIntelHandler(threatIntelService *services.ThreatIntelService) *ThreatIntelHandler {
	return &ThreatIntelHandler{
		threatIntelService: threatIntelService,
	}
}

// ListIndicators returns list of threat intelligence indicators
func (h *ThreatIntelHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	indicatorType := c.Query("indicator_type")
	threatType := c.Query("threat_type")
	isActive := c.Query("is_active")

	indicators, total, err := h.threatIntelService.ListIndicators(page, limit, indicatorType, threatType, isActive)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"indicators": indicators,
		"total":      total,
		"page":       page,
		"limit":      limit,
	})
}

// GetIndicator returns a specific threat intelligence indicator
func (h *ThreatIntelHandler) Get(c *gin.Context) {
	id := c.Param("id")
	indicatorID, err := uuid.Parse(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid indicator ID"})
		return
	}

	indicator, err := h.threatIntelService.GetIndicator(indicatorID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Indicator not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"indicator": indicator})
}

// CreateIndicator creates a new threat intelligence indicator
func (h *ThreatIntelHandler) Create(c *gin.Context) {
	var req struct {
		IndicatorType  string   `json:"indicator_type" binding:"required"`
		IndicatorValue string   `json:"indicator_value" binding:"required"`
		ThreatType     string   `json:"threat_type"`
		MalwareFamily  string   `json:"malware_family"`
		Confidence     int      `json:"confidence"`
		Source         string   `json:"source"`
		SourceURL      string   `json:"source_url"`
		Description    string   `json:"description"`
		Severity       int      `json:"severity"`
		Tags           []string `json:"tags"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	indicator, err := h.threatIntelService.CreateIndicator(
		req.IndicatorType, req.IndicatorValue, req.ThreatType, req.MalwareFamily,
		req.Confidence, req.Source, req.SourceURL, req.Description, req.Severity, req.Tags)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"indicator": indicator})
}

// UpdateIndicator updates an existing threat intelligence indicator
func (h *ThreatIntelHandler) Update(c *gin.Context) {
	id := c.Param("id")
	indicatorID, err := uuid.Parse(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid indicator ID"})
		return
	}

	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err = h.threatIntelService.UpdateIndicator(indicatorID, updates)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Indicator updated successfully"})
}

// DeleteIndicator deletes a threat intelligence indicator
func (h *ThreatIntelHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	indicatorID, err := uuid.Parse(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid indicator ID"})
		return
	}

	err = h.threatIntelService.DeleteIndicator(indicatorID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Indicator deleted successfully"})
}

// IOCLookup performs IOC lookup
func (h *ThreatIntelHandler) IOCLookup(c *gin.Context) {
	indicatorType := c.Query("type")
	indicatorValue := c.Query("value")

	if indicatorType == "" || indicatorValue == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Type and value are required"})
		return
	}

	ti, err := h.threatIntelService.IOCLookup(c.Request.Context(), indicatorType, indicatorValue)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"threat_intelligence": ti})
}

// EnrichEvent enriches an event with threat intelligence
func (h *ThreatIntelHandler) EnrichEvent(c *gin.Context) {
	var event models.Event
	if err := c.ShouldBindJSON(&event); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.threatIntelService.EnrichEvent(c.Request.Context(), &event)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"enriched_event": event})
}

// EnrichAlert enriches an alert with threat intelligence
func (h *ThreatIntelHandler) EnrichAlert(c *gin.Context) {
	alertID := c.Param("alertId")
	if alertID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Alert ID is required"})
		return
	}

	// Get alert from database
	var alert models.Alert
	if err := h.threatIntelService.GetDB().Where("id = ?", alertID).First(&alert).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Alert not found"})
		return
	}

	err := h.threatIntelService.EnrichAlert(c.Request.Context(), &alert)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"enriched_alert": alert})
}

// MITREMapping returns MITRE ATT&CK mapping for a threat
func (h *ThreatIntelHandler) MITREMapping(c *gin.Context) {
	threatType := c.Query("threat_type")
	malwareFamily := c.Query("malware_family")

	if threatType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Threat type is required"})
		return
	}

	tactics, techniques, err := h.threatIntelService.MITREMapping(c.Request.Context(), threatType, malwareFamily)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tactics":    tactics,
		"techniques": techniques,
	})
}

// BulkEnrichment performs bulk enrichment of events/alerts
func (h *ThreatIntelHandler) BulkEnrichment(c *gin.Context) {
	var req struct {
		Items []interface{} `json:"items" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.threatIntelService.BulkEnrichment(c.Request.Context(), req.Items)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Bulk enrichment completed successfully"})
}

// GetThreatStats returns threat intelligence statistics
func (h *ThreatIntelHandler) GetThreatStats(c *gin.Context) {
	stats, err := h.threatIntelService.GetThreatStats(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"stats": stats})
}

// ImportIndicators imports indicators from external sources
func (h *ThreatIntelHandler) ImportIndicators(c *gin.Context) {
	var req struct {
		Source string `json:"source" binding:"required"`
		URL    string `json:"url"`
		Format string `json:"format" binding:"required"`
		Data   string `json:"data"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	count, err := h.threatIntelService.ImportIndicators(req.Source, req.URL, req.Format, req.Data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Import completed successfully",
		"count":   count,
	})
}

// LookupIndicator performs indicator lookup
func (h *ThreatIntelHandler) LookupIndicator(c *gin.Context) {
	indicatorType := c.Param("type")
	indicatorValue := c.Param("value")

	if indicatorType == "" || indicatorValue == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Type and value are required"})
		return
	}

	indicators, err := h.threatIntelService.LookupIndicator(indicatorType, indicatorValue)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"indicators": indicators})
}
