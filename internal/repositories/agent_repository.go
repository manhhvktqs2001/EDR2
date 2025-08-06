package repositories

import (
	"edr-server/internal/models"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type AgentRepository struct {
	db *gorm.DB
}

func NewAgentRepository(db *gorm.DB) *AgentRepository {
	return &AgentRepository{db: db}
}

func (r *AgentRepository) Create(agent *models.Agent) error {
	return r.db.Create(agent).Error
}

func (r *AgentRepository) GetByID(id uuid.UUID) (*models.Agent, error) {
	var agent models.Agent
	err := r.db.First(&agent, "id = ?", id).Error
	return &agent, err
}

func (r *AgentRepository) GetByMAC(macAddress string) (*models.Agent, error) {
	var agent models.Agent
	err := r.db.Where("mac_address = ?", macAddress).First(&agent).Error
	return &agent, err
}

func (r *AgentRepository) Update(id uuid.UUID, updates map[string]interface{}) error {
	return r.db.Model(&models.Agent{}).Where("id = ?", id).Updates(updates).Error
}

func (r *AgentRepository) Delete(id uuid.UUID) error {
	return r.db.Delete(&models.Agent{}, "id = ?", id).Error
}

func (r *AgentRepository) UpdateLastSeen(id uuid.UUID, status string) error {
	return r.db.Model(&models.Agent{}).Where("id = ?", id).Updates(map[string]interface{}{
		"last_seen": time.Now(),
		"status":    status,
	}).Error
}

func (r *AgentRepository) List(page, limit int, status, osType string) ([]models.Agent, int64, error) {
	var agents []models.Agent
	var total int64

	query := r.db.Model(&models.Agent{})

	if status != "" {
		query = query.Where("status = ?", status)
	}
	if osType != "" {
		query = query.Where("os_type = ?", osType)
	}

	query.Count(&total)

	offset := (page - 1) * limit
	err := query.Offset(offset).Limit(limit).Order("created_at DESC").Find(&agents).Error

	return agents, total, err
}

func (r *AgentRepository) Count() (int64, error) {
	var count int64
	err := r.db.Model(&models.Agent{}).Count(&count).Error
	return count, err
}

func (r *AgentRepository) CountByStatus(status string) (int64, error) {
	var count int64
	err := r.db.Model(&models.Agent{}).Where("status = ?", status).Count(&count).Error
	return count, err
}

func (r *AgentRepository) MarkOfflineAgents(cutoff time.Time) error {
	return r.db.Model(&models.Agent{}).Where("last_seen < ? AND status = ?", cutoff, "online").Update("status", "offline").Error
}

func (r *AgentRepository) GetStatusSummary() (map[string]interface{}, error) {
	var results []struct {
		Status string
		Count  int64
	}

	err := r.db.Model(&models.Agent{}).Select("status, count(*) as count").Group("status").Scan(&results).Error
	if err != nil {
		return nil, err
	}

	summary := make(map[string]interface{})
	for _, result := range results {
		summary[result.Status] = result.Count
	}

	return summary, nil
}
