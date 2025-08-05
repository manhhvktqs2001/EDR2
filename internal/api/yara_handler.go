package api

import (
	"net/http"
	"strconv"

	"edr-server/internal/models"
	"edr-server/internal/services"
	"edr-server/internal/websocket"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type YaraHandler struct {
	yaraService *services.YaraService
	wsHub       *websocket.Hub
}

func NewYaraHandler(yaraService *services.YaraService, wsHub *websocket.Hub) *YaraHandler {
	return &YaraHandler{
		yaraService: yaraService,
		wsHub:       wsHub,
	}
}

// List returns list of YARA rules
func (h *YaraHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	category := c.Query("category")
	platform := c.Query("platform")
	isActive := c.Query("is_active")

	rules, total, err := h.yaraService.ListRules(page, limit, category, platform, isActive)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"rules": rules,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

// Create creates a new YARA rule
func (h *YaraHandler) Create(c *gin.Context) {
	var req struct {
		Name        string   `json:"name" binding:"required"`
		Content     string   `json:"content" binding:"required"`
		Description string   `json:"description"`
		Author      string   `json:"author"`
		Reference   string   `json:"reference"`
		Severity    int      `json:"severity"`
		Category    string   `json:"category"`
		Subcategory string   `json:"subcategory"`
		Tags        []string `json:"tags"`
		Platform    string   `json:"platform"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rule := &models.YaraRule{
		Name:        req.Name,
		Content:     req.Content,
		Description: req.Description,
		Author:      req.Author,
		Reference:   req.Reference,
		Severity:    req.Severity,
		Category:    req.Category,
		Subcategory: req.Subcategory,
		Tags:        req.Tags,
		Platform:    req.Platform,
	}
	err := h.yaraService.CreateRule(rule)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Broadcast new rule creation
	h.wsHub.Broadcast("yara_rule_created", map[string]interface{}{
		"rule_id":  rule.ID,
		"name":     rule.Name,
		"category": rule.Category,
		"severity": rule.Severity,
	})

	c.JSON(http.StatusCreated, rule)
}

// Get returns a single YARA rule
func (h *YaraHandler) Get(c *gin.Context) {
	ruleID := c.Param("id")
	id, err := uuid.Parse(ruleID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule_id"})
		return
	}

	rule, err := h.yaraService.GetRule(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}

	c.JSON(http.StatusOK, rule)
}

// Update updates a YARA rule
func (h *YaraHandler) Update(c *gin.Context) {
	ruleID := c.Param("id")
	id, err := uuid.Parse(ruleID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule_id"})
		return
	}

	var req map[string]interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err = h.yaraService.UpdateRule(id, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// Delete deletes a YARA rule
func (h *YaraHandler) Delete(c *gin.Context) {
	ruleID := c.Param("id")
	id, err := uuid.Parse(ruleID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule_id"})
		return
	}

	err = h.yaraService.DeleteRule(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Broadcast rule deletion
	h.wsHub.Broadcast("yara_rule_deleted", map[string]interface{}{
		"rule_id": id,
	})

	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// Deploy deploys a YARA rule to agents
func (h *YaraHandler) Deploy(c *gin.Context) {
	ruleID := c.Param("id")
	id, err := uuid.Parse(ruleID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule_id"})
		return
	}

	var req struct {
		AgentIDs []string `json:"agent_ids"`
		GroupIDs []string `json:"group_ids"`
		Platform string   `json:"platform"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Convert string IDs to UUIDs
	var agentIDs []uuid.UUID
	for _, idStr := range req.AgentIDs {
		if agentID, err := uuid.Parse(idStr); err == nil {
			agentIDs = append(agentIDs, agentID)
		}
	}

	var groupIDs []uuid.UUID
	for _, idStr := range req.GroupIDs {
		if groupID, err := uuid.Parse(idStr); err == nil {
			groupIDs = append(groupIDs, groupID)
		}
	}

	err = h.yaraService.DeployRule(id, agentIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Broadcast rule deployment
	h.wsHub.Broadcast("yara_rule_deployed", map[string]interface{}{
		"rule_id": id,
	})

	c.JSON(http.StatusOK, gin.H{
		"status": "deployed",
	})
}

// Compile compiles a YARA rule
func (h *YaraHandler) Compile(c *gin.Context) {
	ruleID := c.Param("id")
	id, err := uuid.Parse(ruleID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule_id"})
		return
	}

	err = h.yaraService.CompileRule(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "compiled"})
}

// GetDeployments returns deployment status for a rule
func (h *YaraHandler) GetDeployments(c *gin.Context) {
	ruleID := c.Param("id")
	id, err := uuid.Parse(ruleID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule_id"})
		return
	}

	deployments, err := h.yaraService.GetRuleDeployments(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"deployments": deployments})
}
