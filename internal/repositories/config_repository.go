package repositories

import (
	"edr-server/internal/models"

	"gorm.io/gorm"
)

type ConfigRepository struct {
	db *gorm.DB
}

func NewConfigRepository(db *gorm.DB) *ConfigRepository {
	return &ConfigRepository{db: db}
}

func (r *ConfigRepository) GetAll() (map[string]interface{}, error) {
	var configs []models.SystemConfig
	err := r.db.Find(&configs).Error
	if err != nil {
		return nil, err
	}

	result := make(map[string]interface{})
	for _, config := range configs {
		key := config.Category + "." + config.Key
		result[key] = config.Value
	}

	return result, nil
}

func (r *ConfigRepository) UpdateMultiple(updates map[string]interface{}) error {
	tx := r.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	for key, value := range updates {
		// Split key into category and key
		// For simplicity, assume format "category.key"
		if err := tx.Model(&models.SystemConfig{}).Where("category = ? AND key = ?", "general", key).Updates(map[string]interface{}{
			"value": value,
		}).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit().Error
}
