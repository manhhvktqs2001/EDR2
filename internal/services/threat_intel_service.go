package services

import (
	"edr-server/internal/models"
	"edr-server/internal/repositories"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ThreatIntelService struct {
	db              *gorm.DB
	redisClient     *redis.Client
	threatIntelRepo *repositories.ThreatIntelRepository
}

func NewThreatIntelService(db *gorm.DB, redisClient *redis.Client) *ThreatIntelService {
	return &ThreatIntelService{
		db:              db,
		redisClient:     redisClient,
		threatIntelRepo: repositories.NewThreatIntelRepository(db),
	}
}

func (s *ThreatIntelService) ListIndicators(page, limit int, indicatorType, threatType, isActive string) ([]models.ThreatIntelligence, int64, error) {
	return s.threatIntelRepo.List(page, limit, indicatorType, threatType, isActive)
}

func (s *ThreatIntelService) CreateIndicator(indicatorType, indicatorValue, threatType, malwareFamily string, confidence int, source, sourceURL, description string, severity int, tags []string) (*models.ThreatIntelligence, error) {
	indicator := &models.ThreatIntelligence{
		ID:             uuid.New(),
		IndicatorType:  indicatorType,
		IndicatorValue: indicatorValue,
		ThreatType:     threatType,
		MalwareFamily:  malwareFamily,
		Confidence:     &confidence,
		Source:         source,
		SourceURL:      sourceURL,
		Description:    description,
		Severity:       severity,
		IsActive:       true,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	err := s.threatIntelRepo.Create(indicator)
	return indicator, err
}

func (s *ThreatIntelService) GetIndicator(indicatorID uuid.UUID) (*models.ThreatIntelligence, error) {
	return s.threatIntelRepo.GetByID(indicatorID)
}

func (s *ThreatIntelService) UpdateIndicator(indicatorID uuid.UUID, updates map[string]interface{}) error {
	return s.threatIntelRepo.Update(indicatorID, updates)
}

func (s *ThreatIntelService) DeleteIndicator(indicatorID uuid.UUID) error {
	return s.threatIntelRepo.Delete(indicatorID)
}

func (s *ThreatIntelService) ImportIndicators(source, url, format, data string) (int, error) {
	// Implementation for importing indicators from external sources
	return 0, nil
}

func (s *ThreatIntelService) LookupIndicator(indicatorType, indicatorValue string) ([]models.ThreatIntelligence, error) {
	return s.threatIntelRepo.Lookup(indicatorType, indicatorValue)
}
