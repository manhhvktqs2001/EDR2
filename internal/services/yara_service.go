package services

import (
	"edr-server/internal/models"
	"edr-server/internal/repositories"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"gorm.io/gorm"
)

type YaraService struct {
	db          *gorm.DB
	minioClient *minio.Client
	yaraRepo    *repositories.YaraRepository
}

func NewYaraService(db *gorm.DB, minioClient *minio.Client) *YaraService {
	return &YaraService{
		db:          db,
		minioClient: minioClient,
		yaraRepo:    repositories.NewYaraRepository(db),
	}
}

// CreateRule creates a new YARA rule
func (s *YaraService) CreateRule(rule *models.YaraRule) error {
	return s.yaraRepo.Create(rule)
}

// GetRule returns a single YARA rule
func (s *YaraService) GetRule(ruleID uuid.UUID) (*models.YaraRule, error) {
	return s.yaraRepo.GetByID(ruleID)
}

// UpdateRule updates YARA rule information
func (s *YaraService) UpdateRule(ruleID uuid.UUID, updates map[string]interface{}) error {
	return s.yaraRepo.Update(ruleID, updates)
}

// DeleteRule deletes a YARA rule
func (s *YaraService) DeleteRule(ruleID uuid.UUID) error {
	return s.yaraRepo.Delete(ruleID)
}

// ListRules returns list of YARA rules with pagination
func (s *YaraService) ListRules(page, limit int, category, platform, isActive string) ([]models.YaraRule, int64, error) {
	return s.yaraRepo.List(page, limit, category, platform, isActive)
}

// CompileRule compiles a YARA rule
func (s *YaraService) CompileRule(ruleID uuid.UUID) error {
	// Implementation for rule compilation
	// This would typically involve validating and compiling the YARA rule
	// For now, just mark as compiled without MinIO storage
	return s.yaraRepo.MarkCompiled(ruleID)
}

// DeployRule deploys a YARA rule to agents
func (s *YaraService) DeployRule(ruleID uuid.UUID, agentIDs []uuid.UUID) error {
	// Implementation for rule deployment
	// This would typically involve creating deployment records
	return nil
}

// GetRuleDeployments returns deployments for a rule
func (s *YaraService) GetRuleDeployments(ruleID uuid.UUID) ([]models.RuleDeployment, error) {
	return s.yaraRepo.GetDeployments(ruleID)
}
