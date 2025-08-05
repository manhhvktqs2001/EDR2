package api

import (
	"edr-server/internal/services"
	"net/http"

	"github.com/gin-gonic/gin"
)

type QuarantineHandler struct {
	quarantineService *services.QuarantineService
}

func NewQuarantineHandler(quarantineService *services.QuarantineService) *QuarantineHandler {
	return &QuarantineHandler{quarantineService: quarantineService}
}

// POST /api/v1/quarantine/upload
func (h *QuarantineHandler) UploadFile(c *gin.Context) {
	agentID := c.PostForm("agent_id")
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
		return
	}
	quarantineID, err := h.quarantineService.QuarantineFile(agentID, file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"quarantine_id": quarantineID})
}

// GET /api/v1/quarantine/files
func (h *QuarantineHandler) ListFiles(c *gin.Context) {
	files, err := h.quarantineService.ListFiles()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"files": files})
}

// GET /api/v1/quarantine/:id
func (h *QuarantineHandler) GetFile(c *gin.Context) {
	fileID := c.Param("id")
	file, err := h.quarantineService.GetFile(fileID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"file": file})
}

// POST /api/v1/quarantine/:id/restore
func (h *QuarantineHandler) RestoreFile(c *gin.Context) {
	fileID := c.Param("id")
	err := h.quarantineService.RestoreFile(fileID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "File restored"})
}

// DELETE /api/v1/quarantine/:id
func (h *QuarantineHandler) DeleteFile(c *gin.Context) {
	fileID := c.Param("id")
	err := h.quarantineService.DeleteFile(fileID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "File deleted"})
}
