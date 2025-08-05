package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"

	"time"

	"edr-server/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type NotificationService struct {
	db *gorm.DB
}

func NewNotificationService(db *gorm.DB) *NotificationService {
	return &NotificationService{
		db: db,
	}
}

// SendNotification sends notification based on type
func (s *NotificationService) SendNotification(ctx context.Context, notificationType string, config map[string]interface{}, message string, recipients []string) error {
	switch notificationType {
	case "email":
		return s.sendEmail(config, message, recipients)
	case "webhook":
		return s.sendWebhook(config, message)
	case "slack":
		return s.sendSlack(config, message)
	case "teams":
		return s.sendTeams(config, message)
	case "sms":
		return s.sendSMS(config, message, recipients)
	default:
		return fmt.Errorf("unsupported notification type: %s", notificationType)
	}
}

// sendEmail sends email notification
func (s *NotificationService) sendEmail(config map[string]interface{}, message string, recipients []string) error {
	smtpHost := config["smtp_host"].(string)
	smtpPort := config["smtp_port"].(string)
	username := config["username"].(string)
	password := config["password"].(string)
	from := config["from"].(string)

	auth := smtp.PlainAuth("", username, password, smtpHost)

	to := recipients
	subject := "EDR Alert Notification"

	emailBody := fmt.Sprintf("Subject: %s\r\n\r\n%s", subject, message)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, []byte(emailBody))
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// sendWebhook sends webhook notification
func (s *NotificationService) sendWebhook(config map[string]interface{}, message string) error {
	url := config["url"].(string)

	payload := map[string]interface{}{
		"message":   message,
		"timestamp": time.Now().Unix(),
		"source":    "edr-server",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook request failed with status: %d", resp.StatusCode)
	}

	return nil
}

// sendSlack sends Slack notification
func (s *NotificationService) sendSlack(config map[string]interface{}, message string) error {
	webhookURL := config["webhook_url"].(string)
	channel := config["channel"].(string)

	payload := map[string]interface{}{
		"channel":    channel,
		"text":       message,
		"username":   "EDR Bot",
		"icon_emoji": ":warning:",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack payload: %w", err)
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send Slack notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Slack request failed with status: %d", resp.StatusCode)
	}

	return nil
}

// sendTeams sends Microsoft Teams notification
func (s *NotificationService) sendTeams(config map[string]interface{}, message string) error {
	webhookURL := config["webhook_url"].(string)

	payload := map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": "0076D7",
		"summary":    "EDR Alert",
		"sections": []map[string]interface{}{
			{
				"activityTitle":    "EDR Security Alert",
				"activitySubtitle": time.Now().Format("2006-01-02 15:04:05"),
				"text":             message,
			},
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal Teams payload: %w", err)
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send Teams notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Teams request failed with status: %d", resp.StatusCode)
	}

	return nil
}

// sendSMS sends SMS notification (placeholder)
func (s *NotificationService) sendSMS(config map[string]interface{}, message string, recipients []string) error {
	// This is a placeholder - implement actual SMS service integration
	// Could use Twilio, AWS SNS, or other SMS providers
	return fmt.Errorf("SMS notifications not implemented yet")
}

// ProcessAlertNotifications processes notifications for new alerts
func (s *NotificationService) ProcessAlertNotifications(ctx context.Context, alert *models.Alert) error {
	// Get notification settings
	var settings []models.NotificationSetting
	if err := s.db.Where("is_active = ?", true).Find(&settings).Error; err != nil {
		return fmt.Errorf("failed to get notification settings: %w", err)
	}

	for _, setting := range settings {
		// Check if this alert matches the notification criteria
		if s.shouldSendNotification(setting, alert) {
			message := s.buildAlertMessage(alert)

			// Get recipients based on notification type
			recipients := s.getRecipients(setting)

			// Send notification
			if err := s.SendNotification(ctx, setting.Type, setting.Config, message, recipients); err != nil {
				// Log error but don't fail the entire process
				fmt.Printf("Failed to send notification: %v\n", err)
			}
		}
	}

	return nil
}

// shouldSendNotification checks if notification should be sent
func (s *NotificationService) shouldSendNotification(setting models.NotificationSetting, alert *models.Alert) bool {
	// Check severity filter
	severityMatch := false
	for _, severity := range setting.SeverityFilter {
		if int(severity) == alert.Severity {
			severityMatch = true
			break
		}
	}
	if !severityMatch {
		return false
	}

	// Check triggers
	for _, trigger := range setting.Triggers {
		switch trigger {
		case "new_alert":
			if alert.Status == "new" {
				return true
			}
		case "critical_alert":
			if alert.Severity >= 4 {
				return true
			}
		case "agent_offline":
			// This would be handled separately
			return false
		}
	}

	return false
}

// buildAlertMessage builds notification message
func (s *NotificationService) buildAlertMessage(alert *models.Alert) string {
	template := `
🚨 EDR Security Alert

Alert ID: %s
Severity: %d/5
Title: %s
Agent: %s
File: %s
Process: %s
Time: %s

Description: %s

Please investigate immediately.
`

	return fmt.Sprintf(template,
		alert.ID,
		alert.Severity,
		alert.Title,
		alert.Agent.Hostname,
		alert.FileName,
		alert.ProcessName,
		alert.DetectionTime.Format("2006-01-02 15:04:05"),
		alert.Description,
	)
}

// getRecipients gets recipients for notification
func (s *NotificationService) getRecipients(setting models.NotificationSetting) []string {
	// This would typically query the database for recipients
	// For now, return from config
	if recipients, ok := setting.Config["recipients"].([]interface{}); ok {
		var result []string
		for _, r := range recipients {
			if email, ok := r.(string); ok {
				result = append(result, email)
			}
		}
		return result
	}

	return []string{}
}

// GetNotificationSettings returns all notification settings
func (s *NotificationService) GetNotificationSettings() ([]models.NotificationSetting, error) {
	var settings []models.NotificationSetting
	err := s.db.Find(&settings).Error
	return settings, err
}

// CreateNotificationSetting creates a new notification setting
func (s *NotificationService) CreateNotificationSetting(setting *models.NotificationSetting) error {
	return s.db.Create(setting).Error
}

// UpdateNotificationSetting updates a notification setting
func (s *NotificationService) UpdateNotificationSetting(id string, updates map[string]interface{}) error {
	settingID, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid notification setting ID: %w", err)
	}

	return s.db.Model(&models.NotificationSetting{}).Where("id = ?", settingID).Updates(updates).Error
}

// DeleteNotificationSetting deletes a notification setting
func (s *NotificationService) DeleteNotificationSetting(id string) error {
	settingID, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid notification setting ID: %w", err)
	}

	return s.db.Where("id = ?", settingID).Delete(&models.NotificationSetting{}).Error
}

// GetDB returns the database instance
func (s *NotificationService) GetDB() *gorm.DB {
	return s.db
}
