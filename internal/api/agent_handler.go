package api

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"edr-server/internal/models"
	"edr-server/internal/services"
	"edr-server/internal/websocket"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type AgentHandler struct {
	agentService *services.AgentService
	wsHub        *websocket.Hub
	alertService *services.AlertService
}

func NewAgentHandler(agentService *services.AgentService, wsHub *websocket.Hub, alertService *services.AlertService) *AgentHandler {
	return &AgentHandler{
		agentService: agentService,
		wsHub:        wsHub,
		alertService: alertService,
	}
}

// validateAuthToken kiểm tra auth token có hợp lệ không
func (h *AgentHandler) validateAuthToken(authToken string) bool {
	// Token cố định cho hệ thống
	validToken := "edr_system_auth_2025"
	return authToken == validToken
}

// Register handles agent registration
func (h *AgentHandler) Register(c *gin.Context) {
	var req struct {
		AuthToken    string                 `json:"auth_token" binding:"required"` // Yêu cầu auth token
		Hostname     string                 `json:"hostname" binding:"required"`
		IPAddress    string                 `json:"ip_address"`
		MACAddress   string                 `json:"mac_address"`
		OSType       string                 `json:"os_type" binding:"required"`
		OSVersion    string                 `json:"os_version"`
		Architecture string                 `json:"architecture"`
		Version      string                 `json:"version"`
		SystemInfo   map[string]interface{} `json:"system_info"`
		Config       map[string]interface{} `json:"config"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate auth token
	if !h.validateAuthToken(req.AuthToken) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid auth token"})
		return
	}

	// Check if MAC address already registered (chỉ check nếu có MAC)
	if req.MACAddress != "" {
		exists, existingAgentID, existingAPIKey, err := h.agentService.AgentExistsByMAC(req.MACAddress)
		if err != nil {
			// Tiếp tục đăng ký nếu không check được
		} else if exists {
			// MAC đã tồn tại, trả về thông tin agent hiện có
			c.JSON(http.StatusConflict, gin.H{
				"error":    "agent with this MAC address already registered",
				"agent_id": existingAgentID,
				"api_key":  existingAPIKey,
				"message":  "MAC address already registered",
			})
			return
		}
	}

	// Đăng ký agent mới
	agent, err := h.agentService.RegisterAgent(req.Hostname, req.IPAddress, req.MACAddress,
		req.OSType, req.OSVersion, req.Architecture, req.Version, req.SystemInfo)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Broadcast new agent registration
	h.wsHub.Broadcast("agent_registered", map[string]interface{}{
		"agent_id": agent.ID,
		"hostname": agent.Hostname,
		"os_type":  agent.OSType,
	})

	c.JSON(http.StatusCreated, gin.H{
		"success":  true,
		"agent_id": agent.ID,
		"api_key":  agent.APIKey,
		"config":   agent.Config,
		"message":  "Agent registered successfully",
	})
}

// Heartbeat handles agent heartbeat
func (h *AgentHandler) Heartbeat(c *gin.Context) {
	var req struct {
		AgentID string                 `json:"agent_id" binding:"required"`
		Status  string                 `json:"status"`
		Metrics map[string]interface{} `json:"metrics"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	id, err := uuid.Parse(req.AgentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent_id"})
		return
	}

	tasks, err := h.agentService.ProcessHeartbeat(id, req.Status, req.Metrics)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"tasks":  tasks,
	})
}

// ReceiveEvents handles events from agents
func (h *AgentHandler) ReceiveEvents(c *gin.Context) {
	// Lấy agent ID từ header
	agentID := c.GetHeader("X-Agent-ID")
	if agentID == "" {
		// Thử lấy từ context (nếu có middleware auth)
		if agentIDFromContext, exists := c.Get("agent_id"); exists {
			agentID = fmt.Sprintf("%v", agentIDFromContext)
		}
	}

	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "X-Agent-ID header is required or agent not authenticated",
		})
		return
	}

	// Kiểm tra định dạng UUID
	agentUUID, err := uuid.Parse(agentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid agent_id format: must be a valid UUID",
		})
		return
	}

	// Đọc và parse body
	var events []map[string]interface{}
	if err := c.ShouldBindJSON(&events); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid JSON format in request body",
			"details": err.Error(),
		})
		return
	}

	// Kiểm tra mảng events không rỗng
	if len(events) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "events array cannot be empty",
		})
		return
	}

	// Log để debug
	fmt.Printf("Received %d events from agent %s\n", len(events), agentID)

	// Xử lý events
	err = h.agentService.ProcessEvents(agentUUID, events)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "failed to process events",
			"details": err.Error(),
		})
		return
	}

	// Trả về thành công
	c.JSON(http.StatusOK, gin.H{
		"status":       "events_received",
		"events_count": len(events),
		"agent_id":     agentID,
	})
}

// ReceiveAlerts handles alerts from agents
func (h *AgentHandler) ReceiveAlerts(c *gin.Context) {
	var req struct {
		AgentID       string                 `json:"agent_id" binding:"required"`
		RuleName      string                 `json:"rule_name"`
		Severity      int                    `json:"severity"`
		Title         string                 `json:"title"`
		Description   string                 `json:"description"`
		FilePath      string                 `json:"file_path"`
		FileName      string                 `json:"file_name"`
		FileHash      string                 `json:"file_hash"`
		FileSize      int64                  `json:"file_size"`
		DetectionTime string                 `json:"detection_time"`
		Status        string                 `json:"status"`
		EventType     string                 `json:"event_type"`
		Metadata      map[string]interface{} `json:"metadata"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Parse agent ID
	agentID, err := uuid.Parse(req.AgentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent_id"})
		return
	}

	// Parse detection time
	detectionTime, err := time.Parse(time.RFC3339, req.DetectionTime)
	if err != nil {
		detectionTime = time.Now()
	}

	// Create alert
	alert := &models.Alert{
		AgentID:       agentID,
		Severity:      req.Severity,
		Title:         req.Title,
		Description:   req.Description,
		FilePath:      req.FilePath,
		FileName:      req.FileName,
		FileHash:      req.FileHash,
		FileSize:      &req.FileSize,
		DetectionTime: detectionTime,
		Status:        req.Status,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Save alert to database
	err = h.alertService.CreateAlert(alert)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Broadcast alert to connected clients
	h.wsHub.Broadcast("new_alert", map[string]interface{}{
		"alert_id":   alert.ID,
		"agent_id":   alert.AgentID,
		"title":      alert.Title,
		"severity":   alert.Severity,
		"status":     alert.Status,
		"created_at": alert.CreatedAt,
		"file_name":  alert.FileName,
		"rule_name":  req.RuleName,
	})

	c.JSON(http.StatusCreated, gin.H{
		"success":  true,
		"alert_id": alert.ID,
		"message":  "Alert created successfully",
	})
}

// GetTasks returns pending tasks for an agent
func (h *AgentHandler) GetTasks(c *gin.Context) {
	agentID := c.Param("id")
	id, err := uuid.Parse(agentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent_id"})
		return
	}

	tasks, err := h.agentService.GetPendingTasks(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"tasks": tasks})
}

// SubmitTaskResult handles task result submission
func (h *AgentHandler) SubmitTaskResult(c *gin.Context) {
	agentID := c.Param("id")
	taskID := c.Param("taskId")

	var req struct {
		Status string                 `json:"status" binding:"required"`
		Result map[string]interface{} `json:"result"`
		Error  string                 `json:"error"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	agentUUID, err := uuid.Parse(agentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent_id"})
		return
	}

	taskUUID, err := uuid.Parse(taskID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task_id"})
		return
	}

	err = h.agentService.UpdateTaskResult(agentUUID, taskUUID, req.Status, req.Result, req.Error)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "result_received"})
}

// List returns list of agents
func (h *AgentHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	status := c.Query("status")
	osType := c.Query("os_type")

	agents, total, err := h.agentService.ListAgents(page, limit, status, osType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"agents": agents,
		"total":  total,
		"page":   page,
		"limit":  limit,
	})
}

// Get returns a single agent
func (h *AgentHandler) Get(c *gin.Context) {
	agentID := c.Param("id")
	id, err := uuid.Parse(agentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent_id"})
		return
	}

	agent, err := h.agentService.GetAgent(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	c.JSON(http.StatusOK, agent)
}

// Update updates agent information
func (h *AgentHandler) Update(c *gin.Context) {
	agentID := c.Param("id")
	id, err := uuid.Parse(agentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent_id"})
		return
	}

	var req map[string]interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err = h.agentService.UpdateAgent(id, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// CheckExistsByMAC checks if an agent exists by MAC address (requires auth)
func (h *AgentHandler) CheckExistsByMAC(c *gin.Context) {
	// Kiểm tra Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization header required"})
		return
	}

	// Extract token from "Bearer <token>"
	token := ""
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		token = authHeader[7:]
	}

	if !h.validateAuthToken(token) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid auth token"})
		return
	}

	macAddress := c.Query("mac")
	if macAddress == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "mac address is required"})
		return
	}

	exists, agentID, apiKey, err := h.agentService.AgentExistsByMAC(macAddress)
	if err != nil {
		fmt.Printf("Failed to check MAC address: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check agent existence"})
		return
	}

	if exists {
		c.JSON(http.StatusOK, gin.H{
			"exists":   true,
			"agent_id": agentID,
			"api_key":  apiKey,
			"status":   "found",
		})
	} else {
		// Trả về 404 khi không tìm thấy MAC
		c.JSON(http.StatusNotFound, gin.H{
			"exists":  false,
			"status":  "not_found",
			"message": "MAC address not found in database",
		})
	}
}

// Delete deletes an agent
func (h *AgentHandler) Delete(c *gin.Context) {
	agentID := c.Param("id")
	id, err := uuid.Parse(agentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent_id"})
		return
	}

	err = h.agentService.DeleteAgent(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Broadcast agent deletion
	h.wsHub.Broadcast("agent_deleted", map[string]interface{}{
		"agent_id": id,
	})

	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// CreateTask creates a new task for an agent
func (h *AgentHandler) CreateTask(c *gin.Context) {
	agentID := c.Param("id")
	id, err := uuid.Parse(agentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent_id"})
		return
	}

	var req struct {
		TaskType   string                 `json:"task_type" binding:"required"`
		Parameters map[string]interface{} `json:"parameters"`
		Priority   int                    `json:"priority"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	task, err := h.agentService.CreateTask(id, req.TaskType, req.Parameters, req.Priority)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, task)
}

// GetStatus returns detailed agent status
func (h *AgentHandler) GetStatus(c *gin.Context) {
	agentID := c.Param("id")
	id, err := uuid.Parse(agentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent_id"})
		return
	}

	status, err := h.agentService.GetAgentStatus(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, status)
}
