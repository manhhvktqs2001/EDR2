package services

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"io"
	"mime/multipart"
	"time"

	"edr-server/internal/models"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"gorm.io/gorm"
)

type QuarantineService struct {
	db          *gorm.DB
	minioClient *minio.Client
}

func NewQuarantineService(db *gorm.DB, minioClient *minio.Client) *QuarantineService {
	return &QuarantineService{
		db:          db,
		minioClient: minioClient,
	}
}

// QuarantineFile processes and quarantines a file
func (s *QuarantineService) QuarantineFile(agentID string, file *multipart.FileHeader) (string, error) {
	quarantineID := uuid.New().String()
	_, sha256Hash, err := s.calculateFileHashes(file)
	if err != nil {
		return "", fmt.Errorf("failed to calculate file hashes: %w", err)
	}
	fileSize := file.Size
	quarantineRecord := &models.QuarantinedFile{
		ID:               uuid.New(),
		AgentID:          uuid.MustParse(agentID),
		FileName:         file.Filename,
		FileSize:         &fileSize,
		FileHash:         sha256Hash,
		Status:           "quarantined",
		QuarantinePath:   fmt.Sprintf("quarantine/%s", quarantineID),
		QuarantineReason: "Automated quarantine",
		QuarantinedAt:    time.Now(),
		AnalysisResult:   models.JSONB{},
		Metadata:         models.JSONB{},
	}
	if err := s.db.Create(quarantineRecord).Error; err != nil {
		return "", fmt.Errorf("failed to save quarantine record: %w", err)
	}
	if s.minioClient != nil {
		ctx := context.Background()
		src, err := file.Open()
		if err != nil {
			return "", err
		}
		defer src.Close()
		_, err = s.minioClient.PutObject(ctx, "quarantine", quarantineID, src, file.Size, minio.PutObjectOptions{
			ContentType: file.Header.Get("Content-Type"),
		})
		if err != nil {
			return "", fmt.Errorf("failed to upload to MinIO: %w", err)
		}
	}
	go s.analyzeFile(quarantineRecord)
	return quarantineID, nil
}

// ListFiles returns list of quarantined files
func (s *QuarantineService) ListFiles() ([]models.QuarantinedFile, error) {
	var files []models.QuarantinedFile
	err := s.db.Find(&files).Error
	return files, err
}

// GetFile returns a specific quarantined file
func (s *QuarantineService) GetFile(fileID string) (*models.QuarantinedFile, error) {
	var file models.QuarantinedFile
	err := s.db.Where("id = ?", fileID).First(&file).Error
	if err != nil {
		return nil, err
	}
	return &file, nil
}

// RestoreFile restores a quarantined file
func (s *QuarantineService) RestoreFile(fileID string) error {
	var file models.QuarantinedFile
	if err := s.db.Where("id = ?", fileID).First(&file).Error; err != nil {
		return err
	}

	// Update status
	file.Status = "restored"
	file.RestoredAt = &[]time.Time{time.Now()}[0]

	return s.db.Save(&file).Error
}

// DeleteFile permanently deletes a quarantined file
func (s *QuarantineService) DeleteFile(fileID string) error {
	var file models.QuarantinedFile
	if err := s.db.Where("id = ?", fileID).First(&file).Error; err != nil {
		return err
	}

	// Delete from MinIO
	if s.minioClient != nil {
		ctx := context.Background()
		s.minioClient.RemoveObject(ctx, "quarantine", file.QuarantinePath, minio.RemoveObjectOptions{})
	}

	// Delete from database
	return s.db.Delete(&file).Error
}

// calculateFileHashes calculates MD5 and SHA256 hashes
func (s *QuarantineService) calculateFileHashes(file *multipart.FileHeader) (string, string, error) {
	src, err := file.Open()
	if err != nil {
		return "", "", err
	}
	defer src.Close()

	md5Hash := md5.New()
	sha256Hash := sha256.New()

	// Read file and calculate hashes
	buffer := make([]byte, 1024*1024) // 1MB buffer
	for {
		n, err := src.Read(buffer)
		if n > 0 {
			md5Hash.Write(buffer[:n])
			sha256Hash.Write(buffer[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", err
		}
	}

	return fmt.Sprintf("%x", md5Hash.Sum(nil)), fmt.Sprintf("%x", sha256Hash.Sum(nil)), nil
}

// uploadToMinIO uploads file to MinIO storage
func (s *QuarantineService) uploadToMinIO(file *multipart.FileHeader, quarantineID string) error {
	src, err := file.Open()
	if err != nil {
		return err
	}
	defer src.Close()

	// Upload to MinIO
	ctx := context.Background()
	_, err = s.minioClient.PutObject(ctx, "quarantine", quarantineID, src, file.Size, minio.PutObjectOptions{
		ContentType: file.Header.Get("Content-Type"),
	})

	return err
}

// analyzeFile performs file analysis
func (s *QuarantineService) analyzeFile(file *models.QuarantinedFile) {
	// Static analysis (giả lập)
	result := map[string]interface{}{
		"file_type": "unknown",
		"entropy":   0.0,
		"strings":   []string{},
	}
	file.AnalysisResult = result
	s.db.Save(file)
	// TODO: Thêm lookup threat intelligence nếu cần
}
