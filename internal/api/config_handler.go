package api

import (
	"net/http"

	"edr-server/internal/services"

	"github.com/gin-gonic/gin"
)

type ConfigHandler struct {
	configService *services.ConfigService
}

func NewConfigHandler(configService *services.ConfigService) *ConfigHandler {
	return &ConfigHandler{
		configService: configService,
	}
}

// List returns all configurations
func (h *ConfigHandler) List(c *gin.Context) {
	configs, err := h.configService.GetAllConfigs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"configs": configs})
}

// GetByCategory returns configurations by category
func (h *ConfigHandler) GetByCategory(c *gin.Context) {
	category := c.Param("category")
	if category == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "category is required"})
		return
	}

	configs, err := h.configService.GetConfigByCategory(category)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"configs": configs})
}

// Create creates a new configuration
func (h *ConfigHandler) Create(c *gin.Context) {
	var req struct {
		Category    string `json:"category" binding:"required"`
		Key         string `json:"key" binding:"required"`
		Value       string `json:"value" binding:"required"`
		Description string `json:"description"`
		DataType    string `json:"data_type" binding:"required"`
		UpdatedBy   string `json:"updated_by"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.configService.SetConfig(req.Category, req.Key, req.Value, req.Description, req.DataType, req.UpdatedBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Configuration created successfully"})
}

// Update updates a configuration
func (h *ConfigHandler) Update(c *gin.Context) {
	category := c.Param("category")
	key := c.Param("key")
	
	if category == "" || key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "category and key are required"})
		return
	}

	var req struct {
		Value       string `json:"value" binding:"required"`
		Description string `json:"description"`
		DataType    string `json:"data_type"`
		UpdatedBy   string `json:"updated_by"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.configService.SetConfig(category, key, req.Value, req.Description, req.DataType, req.UpdatedBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Configuration updated successfully"})
}

// Delete deletes a configuration
func (h *ConfigHandler) Delete(c *gin.Context) {
	category := c.Param("category")
	key := c.Param("key")
	
	if category == "" || key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "category and key are required"})
		return
	}

	err := h.configService.DeleteConfig(category, key)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Configuration deleted successfully"})
} 