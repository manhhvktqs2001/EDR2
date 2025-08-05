package api

import (
	"net/http"

	"edr-server/internal/models"
	"edr-server/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type NotificationHandler struct {
	notificationService *services.NotificationService
}

func NewNotificationHandler(notificationService *services.NotificationService) *NotificationHandler {
	return &NotificationHandler{
		notificationService: notificationService,
	}
}

// ListNotificationSettings returns all notification settings
func (h *NotificationHandler) List(c *gin.Context) {
	settings, err := h.notificationService.GetNotificationSettings()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"settings": settings})
}

// GetNotificationSetting returns a specific notification setting
func (h *NotificationHandler) Get(c *gin.Context) {
	id := c.Param("id")
	settingID, err := uuid.Parse(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid notification setting ID"})
		return
	}

	// This would typically get from service, but for now return from database
	var setting models.NotificationSetting
	if err := h.notificationService.GetDB().Where("id = ?", settingID).First(&setting).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Notification setting not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"setting": setting})
}

// CreateNotificationSetting creates a new notification setting
func (h *NotificationHandler) Create(c *gin.Context) {
	var setting models.NotificationSetting
	if err := c.ShouldBindJSON(&setting); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.notificationService.CreateNotificationSetting(&setting); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"setting": setting})
}

// UpdateNotificationSetting updates a notification setting
func (h *NotificationHandler) Update(c *gin.Context) {
	id := c.Param("id")
	
	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.notificationService.UpdateNotificationSetting(id, updates); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Notification setting updated successfully"})
}

// DeleteNotificationSetting deletes a notification setting
func (h *NotificationHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	
	if err := h.notificationService.DeleteNotificationSetting(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Notification setting deleted successfully"})
}

// TestNotification tests a notification setting
func (h *NotificationHandler) Test(c *gin.Context) {
	id := c.Param("id")
	settingID, err := uuid.Parse(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid notification setting ID"})
		return
	}

	// Get the notification setting
	var setting models.NotificationSetting
	if err := h.notificationService.GetDB().Where("id = ?", settingID).First(&setting).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Notification setting not found"})
		return
	}

	// Send test notification
	testMessage := "This is a test notification from EDR Server"
	recipients := []string{"test@example.com"} // Default test recipient
	
	if err := h.notificationService.SendNotification(c.Request.Context(), setting.Type, setting.Config, testMessage, recipients); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Test notification sent successfully"})
} 