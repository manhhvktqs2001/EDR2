package repositories

import (
	"edr-server/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ThreatIntelRepository struct {
	db *gorm.DB
}

func NewThreatIntelRepository(db *gorm.DB) *ThreatIntelRepository {
	return &ThreatIntelRepository{db: db}
}

func (r *ThreatIntelRepository) Create(indicator *models.ThreatIntelligence) error {
	return r.db.Create(indicator).Error
}

func (r *ThreatIntelRepository) GetByID(id uuid.UUID) (*models.ThreatIntelligence, error) {
	var indicator models.ThreatIntelligence
	err := r.db.First(&indicator, "id = ?", id).Error
	return &indicator, err
}

func (r *ThreatIntelRepository) Update(id uuid.UUID, updates map[string]interface{}) error {
	return r.db.Model(&models.ThreatIntelligence{}).Where("id = ?", id).Updates(updates).Error
}

func (r *ThreatIntelRepository) Delete(id uuid.UUID) error {
	return r.db.Delete(&models.ThreatIntelligence{}, "id = ?", id).Error
}

func (r *ThreatIntelRepository) List(page, limit int, indicatorType, threatType, isActive string) ([]models.ThreatIntelligence, int64, error) {
	var indicators []models.ThreatIntelligence
	var total int64

	query := r.db.Model(&models.ThreatIntelligence{})

	if indicatorType != "" {
		query = query.Where("indicator_type = ?", indicatorType)
	}
	if threatType != "" {
		query = query.Where("threat_type = ?", threatType)
	}
	if isActive != "" {
		query = query.Where("is_active = ?", isActive == "true")
	}

	query.Count(&total)

	offset := (page - 1) * limit
	err := query.Offset(offset).Limit(limit).Order("created_at DESC").Find(&indicators).Error

	return indicators, total, err
}

func (r *ThreatIntelRepository) Lookup(indicatorType, indicatorValue string) ([]models.ThreatIntelligence, error) {
	var indicators []models.ThreatIntelligence
	err := r.db.Where("indicator_type = ? AND indicator_value = ? AND is_active = ?", indicatorType, indicatorValue, true).Find(&indicators).Error
	return indicators, err
}
