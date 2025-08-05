package api

import (
	"net/http"
	"strconv"

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

// List returns list of threat intelligence indicators
func (h *ThreatIntelHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
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

// Create creates a new threat intelligence indicator
func (h *ThreatIntelHandler) Create(c *gin.Context) {
	var req struct {
		IndicatorType  string   `json:"indicator_type" binding:"required"`
		IndicatorValue string   `json:"indicator_value" binding:"required"`
		ThreatType     string   `json:"threat_type"`
		MalwareFamily  string   `json:"malware_family"`
		Confidence     int      `json:"confidence"`
		Source         string   `json:"source" binding:"required"`
		SourceURL      string   `json:"source_url"`
		Description    string   `json:"description"`
		Severity       int      `json:"severity"`
		Tags           []string `json:"tags"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	indicator, err := h.threatIntelService.CreateIndicator(req.IndicatorType, req.IndicatorValue,
		req.ThreatType, req.MalwareFamily, req.Confidence, req.Source, req.SourceURL,
		req.Description, req.Severity, req.Tags)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, indicator)
}

// Get returns a single threat intelligence indicator
func (h *ThreatIntelHandler) Get(c *gin.Context) {
	indicatorID := c.Param("id")
	id, err := uuid.Parse(indicatorID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid indicator_id"})
		return
	}

	indicator, err := h.threatIntelService.GetIndicator(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "indicator not found"})
		return
	}

	c.JSON(http.StatusOK, indicator)
}

// Update updates a threat intelligence indicator
func (h *ThreatIntelHandler) Update(c *gin.Context) {
	indicatorID := c.Param("id")
	id, err := uuid.Parse(indicatorID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid indicator_id"})
		return
	}

	var req map[string]interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err = h.threatIntelService.UpdateIndicator(id, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// Delete deletes a threat intelligence indicator
func (h *ThreatIntelHandler) Delete(c *gin.Context) {
	indicatorID := c.Param("id")
	id, err := uuid.Parse(indicatorID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid indicator_id"})
		return
	}

	err = h.threatIntelService.DeleteIndicator(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// Import imports threat intelligence indicators from external sources
func (h *ThreatIntelHandler) Import(c *gin.Context) {
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
		"status":   "imported",
		"imported": count,
	})
}

// Lookup looks up a specific indicator value
func (h *ThreatIntelHandler) Lookup(c *gin.Context) {
	indicatorType := c.Param("type")
	indicatorValue := c.Param("value")

	results, err := h.threatIntelService.LookupIndicator(indicatorType, indicatorValue)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"indicator_type":  indicatorType,
		"indicator_value": indicatorValue,
		"results":         results,
		"found":           len(results) > 0,
	})
}
