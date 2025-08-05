package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"edr-server/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"gorm.io/gorm"
)

type AuthMiddleware struct {
	db        *gorm.DB
	secretKey []byte
	rateLimit map[string][]time.Time
}

func NewAuthMiddleware(db *gorm.DB, secretKey string) *AuthMiddleware {
	return &AuthMiddleware{
		db:        db,
		secretKey: []byte(secretKey),
		rateLimit: make(map[string][]time.Time),
	}
}

// AgentAuth validates agent authentication using API key
func (m *AuthMiddleware) AgentAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing API key"})
			c.Abort()
			return
		}

		// Validate API key against database
		var agent models.Agent
		if err := m.db.Where("api_key = ? AND is_active = ?", apiKey, true).First(&agent).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
			c.Abort()
			return
		}

		// Add agent info to context
		c.Set("agent_id", agent.ID.String())
		c.Set("agent_name", agent.Hostname)
		c.Next()
	}
}

// AdminAuth validates admin authentication using JWT
func (m *AuthMiddleware) AdminAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing authorization header"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header"})
			c.Abort()
			return
		}

		// Parse and validate JWT token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return m.secretKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Extract claims
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			c.Set("user_id", claims["user_id"])
			c.Set("role", claims["role"])
			c.Set("username", claims["username"])
		}

		c.Next()
	}
}

// RateLimit implements rate limiting per IP
func (m *AuthMiddleware) RateLimit(requests int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		now := time.Now()

		// Clean old requests
		if requests, exists := m.rateLimit[clientIP]; exists {
			var validRequests []time.Time
			for _, req := range requests {
				if now.Sub(req) < window {
					validRequests = append(validRequests, req)
				}
			}
			m.rateLimit[clientIP] = validRequests
		}

		// Check rate limit
		if len(m.rateLimit[clientIP]) >= requests {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
			c.Abort()
			return
		}

		// Add current request
		m.rateLimit[clientIP] = append(m.rateLimit[clientIP], now)
		c.Next()
	}
}

// AuditLog logs actions for audit trail
func (m *AuthMiddleware) AuditLog(action, resourceType string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user info from context
		userID, _ := c.Get("user_id")

		// Create audit log entry
		auditLog := models.AuditLog{
			Action:       action,
			ResourceType: resourceType,
			UserID:       fmt.Sprintf("%v", userID),
			IPAddress:    c.ClientIP(),
			UserAgent:    c.GetHeader("User-Agent"),
			Success:      true,
			Timestamp:    time.Now(),
		}

		// Save to database
		if m.db != nil {
			m.db.Create(&auditLog)
		}

		c.Next()
	}
}

// InputValidation validates and sanitizes input
func (m *AuthMiddleware) InputValidation() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Validate Content-Type for POST/PUT requests
		if c.Request.Method == "POST" || c.Request.Method == "PUT" {
			contentType := c.GetHeader("Content-Type")
			if !strings.Contains(contentType, "application/json") &&
				!strings.Contains(contentType, "multipart/form-data") {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Content-Type"})
				c.Abort()
				return
			}
		}

		// Validate file uploads
		if c.Request.Method == "POST" && strings.Contains(c.Request.URL.Path, "/upload") {
			if err := m.validateFileUpload(c); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// RBAC implements Role-Based Access Control
func (m *AuthMiddleware) RBAC(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Role not found"})
			c.Abort()
			return
		}

		if role != requiredRole && role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// validateFileUpload validates file uploads
func (m *AuthMiddleware) validateFileUpload(c *gin.Context) error {
	file, err := c.FormFile("file")
	if err != nil {
		return fmt.Errorf("no file uploaded")
	}

	// Check file size (100MB limit)
	if file.Size > 100*1024*1024 {
		return fmt.Errorf("file too large (max 100MB)")
	}

	// Check file extension
	ext := strings.ToLower(filepath.Ext(file.Filename))
	allowedExts := []string{".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js"}

	allowed := false
	for _, allowedExt := range allowedExts {
		if ext == allowedExt {
			allowed = true
			break
		}
	}

	if !allowed {
		return fmt.Errorf("file type not allowed")
	}

	return nil
}

// GenerateJWT generates a JWT token for admin users
func (m *AuthMiddleware) GenerateJWT(userID, username, role string) (string, error) {
	claims := jwt.MapClaims{
		"user_id":  userID,
		"username": username,
		"role":     role,
		"exp":      time.Now().Add(time.Hour * 24).Unix(), // 24 hours
		"iat":      time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secretKey)
}

// GenerateAPIKey generates a secure API key for agents
func (m *AuthMiddleware) GenerateAPIKey() string {
	key := make([]byte, 32)
	rand.Read(key)
	return hex.EncodeToString(key)
}

// ValidateAPIKey validates an API key
func (m *AuthMiddleware) ValidateAPIKey(apiKey string) bool {
	if len(apiKey) != 64 { // 32 bytes = 64 hex chars
		return false
	}

	// Check if it's valid hex
	_, err := hex.DecodeString(apiKey)
	return err == nil
}
