package services

import (
	"edr-server/internal/models"
	"edr-server/internal/repositories"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type TaskService struct {
	db          *gorm.DB
	redisClient *redis.Client
	taskRepo    *repositories.TaskRepository
}

func NewTaskService(db *gorm.DB, redisClient *redis.Client) *TaskService {
	return &TaskService{
		db:          db,
		redisClient: redisClient,
		taskRepo:    repositories.NewTaskRepository(db),
	}
}

func (s *TaskService) ListTasks(page, limit int, status, agentID string) ([]models.AgentTask, int64, error) {
	return s.taskRepo.List(page, limit, status, agentID)
}

func (s *TaskService) GetTask(taskID uuid.UUID) (*models.AgentTask, error) {
	return s.taskRepo.GetByID(taskID)
}

func (s *TaskService) CreateTask(agentID uuid.UUID, taskType string, parameters map[string]interface{}, priority, timeoutSeconds int, createdBy string) (*models.AgentTask, error) {
	task := &models.AgentTask{
		ID:             uuid.New(),
		AgentID:        agentID,
		TaskType:       taskType,
		Parameters:     models.JSONB(parameters),
		Status:         "pending",
		Priority:       priority,
		TimeoutSeconds: timeoutSeconds,
		CreatedBy:      createdBy,
		CreatedAt:      time.Now(),
	}

	err := s.taskRepo.Create(task)
	return task, err
}

func (s *TaskService) UpdateTask(taskID uuid.UUID, updates map[string]interface{}) error {
	return s.taskRepo.Update(taskID, updates)
}

func (s *TaskService) DeleteTask(taskID uuid.UUID) error {
	return s.taskRepo.Delete(taskID)
}

func (s *TaskService) CancelTask(taskID uuid.UUID, cancelledBy, reason string) error {
	return s.taskRepo.Update(taskID, map[string]interface{}{
		"status":        "cancelled",
		"error_message": reason,
	})
}

func (s *TaskService) StartProcessor() {
	// Background task processing
}
