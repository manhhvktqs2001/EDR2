package api

import (
	"net/http"
	"strconv"

	"edr-server/internal/services"
	"edr-server/internal/websocket"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type AgentHandler struct {
	agentService *services.AgentService
	wsHub        *websocket.Hub
}

func NewAgentHandler(agentService *services.AgentService, wsHub *websocket.Hub) *AgentHandler {
	return &AgentHandler{
		agentService: agentService,
		wsHub:        wsHub,
	}
}

// Register handles agent registration
func (h *AgentHandler) Register(c *gin.Context) {
	var req struct {
		Hostname     string                 `json:"hostname" binding:"required"`
		IPAddress    string                 `json:"ip_address"`
		MACAddress   string                 `json:"mac_address"`
		OSType       string                 `json:"os_type" binding:"required"`
		OSVersion    string                 `json:"os_version"`
		Architecture string                 `json:"architecture"`
		Version      string                 `json:"version"`
		Config       map[string]interface{} `json:"config"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	agent, err := h.agentService.RegisterAgent(req.Hostname, req.IPAddress, req.MACAddress,
		req.OSType, req.OSVersion, req.Architecture, req.Version, req.Config)
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
		"agent_id": agent.ID,
		"config":   agent.Config,
	})
}

// Heartbeat handles agent heartbeat
func (h *AgentHandler) Heartbeat(c *gin.Context) {
	agentID := c.Param("id")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id is required"})
		return
	}

	var req struct {
		Status  string                 `json:"status"`
		Metrics map[string]interface{} `json:"metrics"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	id, err := uuid.Parse(agentID)
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
	agentID := c.GetHeader("X-Agent-ID")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Agent-ID header is required"})
		return
	}

	var events []map[string]interface{}
	if err := c.ShouldBindJSON(&events); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	id, err := uuid.Parse(agentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent_id"})
		return
	}

	err = h.agentService.ProcessEvents(id, events)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "events_received"})
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
