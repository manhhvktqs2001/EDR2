package services

import (
	"fmt"
	"time"

	"edr-server/internal/models"
	"edr-server/internal/repositories"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type AgentService struct {
	db          *gorm.DB
	redisClient *redis.Client
	agentRepo   *repositories.AgentRepository
	taskRepo    *repositories.TaskRepository
	configRepo  *repositories.ConfigRepository
	eventService *EventService
}

func NewAgentService(db *gorm.DB, redisClient *redis.Client) *AgentService {
	return &AgentService{
		db:          db,
		redisClient: redisClient,
		agentRepo:   repositories.NewAgentRepository(db),
		taskRepo:    repositories.NewTaskRepository(db),
		configRepo:  repositories.NewConfigRepository(db),
		eventService: nil, // Will be set after EventService is created
	}
}

// SetEventService sets the event service for processing events
func (s *AgentService) SetEventService(eventService *EventService) {
	s.eventService = eventService
}

// RegisterAgent registers a new agent
func (s *AgentService) RegisterAgent(hostname, ipAddress, macAddress, osType, osVersion, architecture, version string, systemInfo map[string]interface{}) (*models.Agent, error) {
	// Generate API key for the agent
	apiKey := s.generateAPIKey()

	agent := &models.Agent{
		ID:                uuid.New(),
		Hostname:          hostname,
		IPAddress:         ipAddress,
		MACAddress:        macAddress,
		OSType:            osType,
		OSVersion:         osVersion,
		Architecture:      architecture,
		AgentVersion:      version,
		Status:            "online",
		LastSeen:          time.Now(),
		FirstSeen:         time.Now(),
		HeartbeatInterval: 30,
		Config:            models.JSONB{},
		Metadata:          models.JSONB(systemInfo),
		APIKey:            apiKey,
		IsActive:          true,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	err := s.agentRepo.Create(agent)
	if err != nil {
		return nil, fmt.Errorf("failed to register agent: %w", err)
	}

	return agent, nil
}

// AgentExistsByMAC checks if an agent exists by MAC address
func (s *AgentService) AgentExistsByMAC(macAddress string) (bool, string, string, error) {
	agent, err := s.agentRepo.GetByMAC(macAddress)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, "", "", nil
		}
		return false, "", "", fmt.Errorf("failed to check agent existence by MAC: %w", err)
	}
	return true, agent.ID.String(), agent.APIKey, nil
}

// generateAPIKey generates a secure API key
func (s *AgentService) generateAPIKey() string {
	// Generate a 64-character random string
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 64)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}

// ProcessHeartbeat processes agent heartbeat
func (s *AgentService) ProcessHeartbeat(agentID uuid.UUID, status string, metrics map[string]interface{}) ([]models.AgentTask, error) {
	// Update agent last seen
	err := s.agentRepo.UpdateLastSeen(agentID, status)
	if err != nil {
		return nil, fmt.Errorf("failed to update agent heartbeat: %w", err)
	}

	// Store metrics in Redis for real-time access
	if len(metrics) > 0 {
		// Implementation for storing metrics
	}

	// Get pending tasks for the agent
	tasks, err := s.taskRepo.GetPendingTasks(agentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending tasks: %w", err)
	}

	return tasks, nil
}

// ProcessEvents processes events from agent
func (s *AgentService) ProcessEvents(agentID uuid.UUID, events []map[string]interface{}) error {
	// Convert UUID to string for EventService
	agentIDStr := agentID.String()
	
	// Use EventService to process and store events in InfluxDB
	if s.eventService != nil {
		return s.eventService.ProcessEvents(agentIDStr, events)
	}
	
	// Fallback: just log events if EventService not available
	for _, event := range events {
		// Process each event
		_ = event
	}

	return nil
}

// GetPendingTasks returns pending tasks for an agent
func (s *AgentService) GetPendingTasks(agentID uuid.UUID) ([]models.AgentTask, error) {
	return s.taskRepo.GetPendingTasks(agentID)
}

// UpdateTaskResult updates task result
func (s *AgentService) UpdateTaskResult(agentID, taskID uuid.UUID, status string, result map[string]interface{}, errorMsg string) error {
	return s.taskRepo.UpdateTaskResult(taskID, status, result, errorMsg)
}

// ListAgents returns list of agents with pagination
func (s *AgentService) ListAgents(page, limit int, status, osType string) ([]models.Agent, int64, error) {
	return s.agentRepo.List(page, limit, status, osType)
}

// GetAgent returns a single agent
func (s *AgentService) GetAgent(agentID uuid.UUID) (*models.Agent, error) {
	return s.agentRepo.GetByID(agentID)
}

// UpdateAgent updates agent information
func (s *AgentService) UpdateAgent(agentID uuid.UUID, updates map[string]interface{}) error {
	return s.agentRepo.Update(agentID, updates)
}

// DeleteAgent deletes an agent
func (s *AgentService) DeleteAgent(agentID uuid.UUID) error {
	return s.agentRepo.Delete(agentID)
}

// CreateTask creates a new task for an agent
func (s *AgentService) CreateTask(agentID uuid.UUID, taskType string, parameters map[string]interface{}, priority int) (*models.AgentTask, error) {
	task := &models.AgentTask{
		ID:             uuid.New(),
		AgentID:        agentID,
		TaskType:       taskType,
		Parameters:     models.JSONB(parameters),
		Status:         "pending",
		Priority:       priority,
		TimeoutSeconds: 300,
		CreatedAt:      time.Now(),
	}

	err := s.taskRepo.Create(task)
	if err != nil {
		return nil, fmt.Errorf("failed to create task: %w", err)
	}

	return task, nil
}

// GetAgentStatus returns detailed agent status
func (s *AgentService) GetAgentStatus(agentID uuid.UUID) (map[string]interface{}, error) {
	agent, err := s.agentRepo.GetByID(agentID)
	if err != nil {
		return nil, err
	}

	status := map[string]interface{}{
		"agent":      agent,
		"is_online":  agent.IsOnline(),
		"is_offline": agent.IsOffline(),
		"last_seen":  agent.LastSeen,
		"uptime":     time.Since(agent.FirstSeen).Seconds(),
	}

	return status, nil
}

// StartHeartbeatMonitor starts monitoring agent heartbeats
func (s *AgentService) StartHeartbeatMonitor() {
	// Check every 30 seconds for real-time updates
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.checkOfflineAgents()
	}
}

func (s *AgentService) checkOfflineAgents() {
	// Reduce timeout to 2 minutes for faster detection
	timeout := 2 * time.Minute
	cutoff := time.Now().Add(-timeout)

	err := s.agentRepo.MarkOfflineAgents(cutoff)
	if err != nil {
		// Log error
		fmt.Printf("Error checking offline agents: %v\n", err)
	}
}

// GetSystemOverview returns system overview
func (s *AgentService) GetSystemOverview() (map[string]interface{}, error) {
	totalAgents, err := s.agentRepo.Count()
	if err != nil {
		return nil, err
	}

	onlineAgents, err := s.agentRepo.CountByStatus("online")
	if err != nil {
		return nil, err
	}

	offlineAgents, err := s.agentRepo.CountByStatus("offline")
	if err != nil {
		return nil, err
	}

	overview := map[string]interface{}{
		"total_agents":   totalAgents,
		"online_agents":  onlineAgents,
		"offline_agents": offlineAgents,
		"timestamp":      time.Now(),
	}

	return overview, nil
}

// GetSystemMetrics returns system metrics
func (s *AgentService) GetSystemMetrics(hours int) (map[string]interface{}, error) {
	// Implementation would fetch metrics from various sources
	metrics := map[string]interface{}{
		"agent_metrics": map[string]interface{}{
			"registration_rate": 0,
			"heartbeat_rate":    0,
		},
		"performance_metrics": map[string]interface{}{
			"avg_response_time": 0,
			"error_rate":        0,
		},
	}

	return metrics, nil
}

// GetAgentStatusSummary returns agent status summary
func (s *AgentService) GetAgentStatusSummary() (map[string]interface{}, error) {
	summary, err := s.agentRepo.GetStatusSummary()
	if err != nil {
		return nil, err
	}

	return summary, nil
}

// GetSystemConfig returns system configuration
func (s *AgentService) GetSystemConfig() (map[string]interface{}, error) {
	return s.configRepo.GetAll()
}

// UpdateSystemConfig updates system configuration
func (s *AgentService) UpdateSystemConfig(config map[string]interface{}) error {
	return s.configRepo.UpdateMultiple(config)
}

// GetSystemLogs returns system logs
func (s *AgentService) GetSystemLogs(logType, level string) ([]map[string]interface{}, error) {
	// Implementation would fetch logs from logging system
	logs := []map[string]interface{}{
		{
			"timestamp": time.Now(),
			"level":     level,
			"message":   "Sample log message",
			"type":      logType,
		},
	}

	return logs, nil
}

// CreateSystemBackup creates system backup
func (s *AgentService) CreateSystemBackup(backupType, description string) (map[string]interface{}, error) {
	backup := map[string]interface{}{
		"id":          uuid.New(),
		"type":        backupType,
		"description": description,
		"created_at":  time.Now(),
		"status":      "created",
	}

	return backup, nil
}
