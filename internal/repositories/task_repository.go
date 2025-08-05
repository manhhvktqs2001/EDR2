package repositories

import (
	"edr-server/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type TaskRepository struct {
	db *gorm.DB
}

func NewTaskRepository(db *gorm.DB) *TaskRepository {
	return &TaskRepository{db: db}
}

func (r *TaskRepository) Create(task *models.AgentTask) error {
	return r.db.Create(task).Error
}

func (r *TaskRepository) GetByID(id uuid.UUID) (*models.AgentTask, error) {
	var task models.AgentTask
	err := r.db.Preload("Agent").First(&task, "id = ?", id).Error
	return &task, err
}

func (r *TaskRepository) Update(id uuid.UUID, updates map[string]interface{}) error {
	return r.db.Model(&models.AgentTask{}).Where("id = ?", id).Updates(updates).Error
}

func (r *TaskRepository) Delete(id uuid.UUID) error {
	return r.db.Delete(&models.AgentTask{}, "id = ?", id).Error
}

func (r *TaskRepository) GetPendingTasks(agentID uuid.UUID) ([]models.AgentTask, error) {
	var tasks []models.AgentTask
	err := r.db.Where("agent_id = ? AND status = ?", agentID, "pending").Order("priority DESC, created_at ASC").Find(&tasks).Error
	return tasks, err
}

func (r *TaskRepository) UpdateTaskResult(taskID uuid.UUID, status string, result map[string]interface{}, errorMsg string) error {
	updates := map[string]interface{}{
		"status": status,
		"result": models.JSONB(result),
	}
	if errorMsg != "" {
		updates["error_message"] = errorMsg
	}
	if status == "completed" {
		updates["completed_at"] = "NOW()"
	}
	return r.db.Model(&models.AgentTask{}).Where("id = ?", taskID).Updates(updates).Error
}

func (r *TaskRepository) List(page, limit int, status, agentID string) ([]models.AgentTask, int64, error) {
	var tasks []models.AgentTask
	var total int64

	query := r.db.Model(&models.AgentTask{}).Preload("Agent")

	if status != "" {
		query = query.Where("status = ?", status)
	}
	if agentID != "" {
		query = query.Where("agent_id = ?", agentID)
	}

	query.Count(&total)

	offset := (page - 1) * limit
	err := query.Offset(offset).Limit(limit).Order("created_at DESC").Find(&tasks).Error

	return tasks, total, err
}
