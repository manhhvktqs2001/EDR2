package api

import (
	"net/http"
	"strconv"

	"edr-server/internal/services"
	"edr-server/internal/websocket"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type TaskHandler struct {
	taskService *services.TaskService
	wsHub       *websocket.Hub
}

func NewTaskHandler(taskService *services.TaskService, wsHub *websocket.Hub) *TaskHandler {
	return &TaskHandler{
		taskService: taskService,
		wsHub:       wsHub,
	}
}

// List returns list of tasks
func (h *TaskHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	status := c.Query("status")
	agentID := c.Query("agent_id")

	tasks, total, err := h.taskService.ListTasks(page, limit, status, agentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"tasks": tasks,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

// Get returns a single task
func (h *TaskHandler) Get(c *gin.Context) {
	taskID := c.Param("id")
	id, err := uuid.Parse(taskID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task_id"})
		return
	}

	task, err := h.taskService.GetTask(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}

	c.JSON(http.StatusOK, task)
}

// Create creates a new task
func (h *TaskHandler) Create(c *gin.Context) {
	var req struct {
		AgentID        string                 `json:"agent_id" binding:"required"`
		TaskType       string                 `json:"task_type" binding:"required"`
		Parameters     map[string]interface{} `json:"parameters"`
		Priority       int                    `json:"priority"`
		TimeoutSeconds int                    `json:"timeout_seconds"`
		CreatedBy      string                 `json:"created_by"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	agentID, err := uuid.Parse(req.AgentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent_id"})
		return
	}

	task, err := h.taskService.CreateTask(agentID, req.TaskType, req.Parameters,
		req.Priority, req.TimeoutSeconds, req.CreatedBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Broadcast new task creation
	h.wsHub.Broadcast("task_created", map[string]interface{}{
		"task_id":   task.ID,
		"agent_id":  task.AgentID,
		"task_type": task.TaskType,
		"priority":  task.Priority,
	})

	c.JSON(http.StatusCreated, task)
}

// Update updates a task
func (h *TaskHandler) Update(c *gin.Context) {
	taskID := c.Param("id")
	id, err := uuid.Parse(taskID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task_id"})
		return
	}

	var req map[string]interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err = h.taskService.UpdateTask(id, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// Delete deletes a task
func (h *TaskHandler) Delete(c *gin.Context) {
	taskID := c.Param("id")
	id, err := uuid.Parse(taskID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task_id"})
		return
	}

	err = h.taskService.DeleteTask(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// Cancel cancels a task
func (h *TaskHandler) Cancel(c *gin.Context) {
	taskID := c.Param("id")
	id, err := uuid.Parse(taskID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task_id"})
		return
	}

	var req struct {
		CancelledBy string `json:"cancelled_by"`
		Reason      string `json:"reason"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err = h.taskService.CancelTask(id, req.CancelledBy, req.Reason)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Broadcast task cancellation
	h.wsHub.Broadcast("task_cancelled", map[string]interface{}{
		"task_id": id,
		"reason":  req.Reason,
	})

	c.JSON(http.StatusOK, gin.H{"status": "cancelled"})
}
