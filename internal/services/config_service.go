package services

import (
	"encoding/json"
	"fmt"
	"strconv"

	"edr-server/internal/models"

	"gorm.io/gorm"
)

type ConfigService struct {
	db *gorm.DB
}

func NewConfigService(db *gorm.DB) *ConfigService {
	return &ConfigService{
		db: db,
	}
}

// GetConfig retrieves a configuration value
func (s *ConfigService) GetConfig(category, key string) (string, error) {
	var config models.SystemConfig
	err := s.db.Where("category = ? AND key = ?", category, key).First(&config).Error
	if err != nil {
		return "", fmt.Errorf("config not found: %s.%s", category, key)
	}
	return config.Value, nil
}

// SetConfig sets a configuration value
func (s *ConfigService) SetConfig(category, key, value, description string, dataType string, updatedBy string) error {
	var config models.SystemConfig
	
	// Check if config exists
	err := s.db.Where("category = ? AND key = ?", category, key).First(&config).Error
	if err == nil {
		// Update existing config
		updates := map[string]interface{}{
			"value":        value,
			"description":  description,
			"data_type":    dataType,
			"updated_by":   updatedBy,
		}
		return s.db.Model(&config).Updates(updates).Error
	} else {
		// Create new config
		config = models.SystemConfig{
			Category:    category,
			Key:         key,
			Value:       value,
			Description: description,
			DataType:    dataType,
			UpdatedBy:   updatedBy,
		}
		return s.db.Create(&config).Error
	}
}

// GetConfigByCategory retrieves all configs for a category
func (s *ConfigService) GetConfigByCategory(category string) ([]models.SystemConfig, error) {
	var configs []models.SystemConfig
	err := s.db.Where("category = ?", category).Find(&configs).Error
	return configs, err
}

// GetAllConfigs retrieves all configurations
func (s *ConfigService) GetAllConfigs() ([]models.SystemConfig, error) {
	var configs []models.SystemConfig
	err := s.db.Find(&configs).Error
	return configs, err
}

// DeleteConfig deletes a configuration
func (s *ConfigService) DeleteConfig(category, key string) error {
	return s.db.Where("category = ? AND key = ?", category, key).Delete(&models.SystemConfig{}).Error
}

// GetIntConfig retrieves a configuration value as integer
func (s *ConfigService) GetIntConfig(category, key string) (int, error) {
	value, err := s.GetConfig(category, key)
	if err != nil {
		return 0, err
	}
	
	intValue, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid integer value for %s.%s: %s", category, key, value)
	}
	
	return intValue, nil
}

// GetBoolConfig retrieves a configuration value as boolean
func (s *ConfigService) GetBoolConfig(category, key string) (bool, error) {
	value, err := s.GetConfig(category, key)
	if err != nil {
		return false, err
	}
	
	boolValue, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("invalid boolean value for %s.%s: %s", category, key, value)
	}
	
	return boolValue, nil
}

// GetJSONConfig retrieves a configuration value as JSON
func (s *ConfigService) GetJSONConfig(category, key string) (map[string]interface{}, error) {
	value, err := s.GetConfig(category, key)
	if err != nil {
		return nil, err
	}
	
	var jsonValue map[string]interface{}
	err = json.Unmarshal([]byte(value), &jsonValue)
	if err != nil {
		return nil, fmt.Errorf("invalid JSON value for %s.%s: %s", category, key, value)
	}
	
	return jsonValue, nil
}

// SetIntConfig sets an integer configuration value
func (s *ConfigService) SetIntConfig(category, key string, value int, description, updatedBy string) error {
	return s.SetConfig(category, key, strconv.Itoa(value), description, "integer", updatedBy)
}

// SetBoolConfig sets a boolean configuration value
func (s *ConfigService) SetBoolConfig(category, key string, value bool, description, updatedBy string) error {
	return s.SetConfig(category, key, strconv.FormatBool(value), description, "boolean", updatedBy)
}

// SetJSONConfig sets a JSON configuration value
func (s *ConfigService) SetJSONConfig(category, key string, value map[string]interface{}, description, updatedBy string) error {
	jsonBytes, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	
	return s.SetConfig(category, key, string(jsonBytes), description, "json", updatedBy)
}

// InitializeDefaultConfigs initializes default system configurations
func (s *ConfigService) InitializeDefaultConfigs() error {
	defaultConfigs := []models.SystemConfig{
		{
			Category:    "general",
			Key:         "system_name",
			Value:       "EDR System",
			Description: "Name of the EDR system",
			DataType:    "string",
		},
		{
			Category:    "general",
			Key:         "version",
			Value:       "1.0.0",
			Description: "System version",
			DataType:    "string",
		},
		{
			Category:    "general",
			Key:         "retention_days",
			Value:       "90",
			Description: "Data retention period in days",
			DataType:    "integer",
		},
		{
			Category:    "alerts",
			Key:         "auto_resolve_days",
			Value:       "30",
			Description: "Auto-resolve alerts after N days",
			DataType:    "integer",
		},
		{
			Category:    "alerts",
			Key:         "max_severity",
			Value:       "5",
			Description: "Maximum alert severity level",
			DataType:    "integer",
		},
		{
			Category:    "agents",
			Key:         "heartbeat_timeout",
			Value:       "300",
			Description: "Agent heartbeat timeout in seconds",
			DataType:    "integer",
		},
		{
			Category:    "agents",
			Key:         "default_heartbeat_interval",
			Value:       "30",
			Description: "Default heartbeat interval in seconds",
			DataType:    "integer",
		},
		{
			Category:    "yara",
			Key:         "max_rules_per_agent",
			Value:       "1000",
			Description: "Maximum YARA rules per agent",
			DataType:    "integer",
		},
		{
			Category:    "yara",
			Key:         "auto_compile",
			Value:       "true",
			Description: "Auto-compile YARA rules on upload",
			DataType:    "boolean",
		},
		{
			Category:    "notifications",
			Key:         "email_enabled",
			Value:       "false",
			Description: "Enable email notifications",
			DataType:    "boolean",
		},
		{
			Category:    "notifications",
			Key:         "webhook_enabled",
			Value:       "true",
			Description: "Enable webhook notifications",
			DataType:    "boolean",
		},
		{
			Category:    "performance",
			Key:         "event_batch_size",
			Value:       "1000",
			Description: "Event processing batch size",
			DataType:    "integer",
		},
		{
			Category:    "performance",
			Key:         "cleanup_interval_hours",
			Value:       "24",
			Description: "Database cleanup interval in hours",
			DataType:    "integer",
		},
		{
			Category:    "security",
			Key:         "max_login_attempts",
			Value:       "5",
			Description: "Maximum login attempts before lockout",
			DataType:    "integer",
		},
		{
			Category:    "security",
			Key:         "session_timeout_minutes",
			Value:       "60",
			Description: "Session timeout in minutes",
			DataType:    "integer",
		},
	}
	
	for _, config := range defaultConfigs {
		// Check if config already exists
		var existing models.SystemConfig
		err := s.db.Where("category = ? AND key = ?", config.Category, config.Key).First(&existing).Error
		if err != nil {
			// Config doesn't exist, create it
			if err := s.db.Create(&config).Error; err != nil {
				return fmt.Errorf("failed to create config %s.%s: %w", config.Category, config.Key, err)
			}
		}
	}
	
	return nil
}

// GetDB returns the database instance
func (s *ConfigService) GetDB() *gorm.DB {
	return s.db
} 