package api

import (
	"net/http"

	"edr-server/internal/services"

	"github.com/gin-gonic/gin"
)

type SystemHandler struct {
	agentService *services.AgentService
}

func NewSystemHandler(agentService *services.AgentService) *SystemHandler {
	return &SystemHandler{
		agentService: agentService,
	}
}

// GetConfig returns system configuration
func (h *SystemHandler) GetConfig(c *gin.Context) {
	config, err := h.agentService.GetSystemConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, config)
}

// UpdateConfig updates system configuration
func (h *SystemHandler) UpdateConfig(c *gin.Context) {
	var req map[string]interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.agentService.UpdateSystemConfig(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// GetLogs returns system logs
func (h *SystemHandler) GetLogs(c *gin.Context) {
	logType := c.DefaultQuery("type", "all")
	level := c.DefaultQuery("level", "info")

	logs, err := h.agentService.GetSystemLogs(logType, level)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"logs": logs})
}

// CreateBackup creates system backup
func (h *SystemHandler) CreateBackup(c *gin.Context) {
	var req struct {
		Type        string `json:"type" binding:"required"`
		Description string `json:"description"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	backup, err := h.agentService.CreateSystemBackup(req.Type, req.Description)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, backup)
}
