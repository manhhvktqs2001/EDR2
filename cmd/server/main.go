package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"edr-server/internal/api"
	"edr-server/internal/config"
	"edr-server/internal/database"
	"edr-server/internal/middleware"
	"edr-server/internal/services"
	"edr-server/internal/websocket"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/minio/minio-go/v7"
	"gorm.io/gorm"
)

var startTime = time.Now()

// checkService checks if a service is running on a specific port
func checkService(port string) bool {
	// Try multiple addresses to check if service is running
	addresses := []string{
		"localhost:" + port,
		"127.0.0.1:" + port,
		"0.0.0.0:" + port,
	}

	for _, addr := range addresses {
		conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// startRedis starts Redis server if not running
func startRedis() {
	if checkService("6379") {
		log.Println("✅ Redis already running on port 6379")
		return
	}

	log.Println("🚀 Starting Redis server...")
	cmd := exec.Command("redis-server")
	cmd.Start()

	// Wait a bit for Redis to start
	time.Sleep(3 * time.Second)

	if checkService("6379") {
		log.Println("✅ Redis started successfully")
	} else {
		log.Println("⚠️  Redis failed to start (may not be installed)")
	}
}

// startInfluxDB starts InfluxDB server if not running
func startInfluxDB() {
	if checkService("8086") {
		log.Println("✅ InfluxDB already running on port 8086")
		return
	}

	log.Println("🚀 Starting InfluxDB server...")
	cmd := exec.Command("influxd.exe")
	cmd.Start()

	// Wait a bit for InfluxDB to start
	time.Sleep(5 * time.Second)

	if checkService("8086") {
		log.Println("✅ InfluxDB started successfully")
	} else {
		log.Println("⚠️  InfluxDB failed to start (may not be installed)")
	}
}

// startMinIO starts MinIO server if not running
func startMinIO() {
	if checkService("9000") {
		log.Println("✅ MinIO already running on port 9000")
		return
	}

	log.Println("🚀 Starting MinIO server...")

	// Create data directory if it doesn't exist
	dataDir := "C:\\minio-data"
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			log.Printf("⚠️  Failed to create MinIO data directory: %v", err)
			return
		}
	}

	// Try different paths for minio.exe
	minioPaths := []string{
		"C:\\minio-data\\minio.exe",
		"minio.exe",
		"C:\\Program Files\\MinIO\\minio.exe",
		"C:\\Program Files (x86)\\MinIO\\minio.exe",
	}

	var minioPath string
	for _, path := range minioPaths {
		if _, err := os.Stat(path); err == nil {
			minioPath = path
			log.Printf("🔍 Found MinIO at: %s", path)
			break
		}
	}

	if minioPath == "" {
		log.Println("⚠️  MinIO not found, please install MinIO or place minio.exe in C:\\minio-data\\")
		log.Println("📥 Download MinIO from: https://min.io/download")
		return
	}

	// Kill any existing MinIO processes
	exec.Command("taskkill", "/F", "/IM", "minio.exe").Run()

	// Start MinIO server
	cmd := exec.Command(minioPath, "server", dataDir, "--address", ":9000", "--console-address", ":9001")
	cmd.Dir = dataDir

	// Set environment variables for better compatibility
	cmd.Env = append(os.Environ(),
		"MINIO_ROOT_USER=minioadmin",
		"MINIO_ROOT_PASSWORD=minioadmin",
	)

	// Start in background
	if err := cmd.Start(); err != nil {
		log.Printf("⚠️  Failed to start MinIO: %v", err)
		return
	}

	// Wait longer for MinIO to start
	log.Println("⏳ Waiting for MinIO to start...")
	time.Sleep(10 * time.Second)

	// Check multiple times if MinIO is running
	for i := 0; i < 5; i++ {
		if checkService("9000") {
			log.Println("✅ MinIO started successfully")
			log.Println("🌐 MinIO Console available at: http://localhost:9001")
			log.Println("🔑 Default credentials: minioadmin / minioadmin")
			return
		}
		time.Sleep(2 * time.Second)
	}

	log.Println("⚠️  MinIO failed to start after multiple attempts")
}

func main() {
	log.Println("🚀 Starting EDR Server...")

	// Start required services
	log.Println("🔧 Checking and starting required services...")
	startRedis()
	startInfluxDB()
	startMinIO()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Printf("⚠️  Failed to load config: %v, using defaults", err)
		// Use default config if loading fails
		cfg = &config.Config{
			Server: config.ServerConfig{
				Address: "localhost:5000",
				Mode:    "debug",
			},
		}
	}

	// Debug: Print the loaded configuration
	log.Printf("🔧 Loaded server address: %s", cfg.Server.Address)
	log.Printf("🔧 Loaded server mode: %s", cfg.Server.Mode)

	// Initialize database connections with error handling
	log.Println("📊 Connecting to databases...")

	var db *gorm.DB
	var influxDB influxdb2.Client
	var redisClient *redis.Client
	var minioClient *minio.Client

	// Try to connect to PostgreSQL
	db, err = database.InitPostgreSQL(cfg.Database.PostgreSQL)
	if err != nil {
		log.Printf("⚠️  PostgreSQL connection failed: %v, continuing without database", err)
		db = nil
	} else {
		log.Println("✅ PostgreSQL connected")
	}

	// Try to connect to InfluxDB
	influxDB, err = database.InitInfluxDB(cfg.Database.InfluxDB)
	if err != nil {
		log.Printf("⚠️  InfluxDB connection failed: %v, continuing without InfluxDB", err)
		influxDB = nil
	} else {
		log.Println("✅ InfluxDB connected")
	}

	// Try to connect to Redis
	redisClient, err = database.InitRedis(cfg.Database.Redis)
	if err != nil {
		log.Printf("⚠️  Redis connection failed: %v, continuing without Redis", err)
		redisClient = nil
	} else {
		log.Println("✅ Redis connected")
	}

	// Try to connect to MinIO
	minioClient, err = database.InitMinIO(cfg.Storage.MinIO)
	if err != nil {
		log.Printf("⚠️  MinIO connection failed: %v, continuing without MinIO", err)
		minioClient = nil
	} else {
		log.Println("✅ MinIO connected")
	}

	// Initialize services with nil checks
	log.Println("⚙️  Initializing services...")

	agentService := services.NewAgentService(db, redisClient)
	yaraService := services.NewYaraService(db, minioClient)
	alertService := services.NewAlertService(db, influxDB, redisClient)
	eventService := services.NewEventService(influxDB, redisClient)
	taskService := services.NewTaskService(db, redisClient)
	threatIntelService := services.NewThreatIntelService(db, redisClient)
	quarantineService := services.NewQuarantineService(db, minioClient)
	quarantineHandler := api.NewQuarantineHandler(quarantineService)

	// Initialize analytics service
	analyticsService := services.NewAnalyticsService(db, influxDB, redisClient)
	analyticsHandler := api.NewAnalyticsHandler(analyticsService)

	// Initialize performance service
	performanceService := services.NewPerformanceService(db, influxDB, redisClient)

	// Initialize notification service
	notificationService := services.NewNotificationService(db)

	// Initialize config service
	configService := services.NewConfigService(db)

	// Initialize auth middleware
	authMiddleware := middleware.NewAuthMiddleware(db, cfg.Security.JWTSecret)

	log.Println("✅ Services initialized")

	// Initialize WebSocket hub
	wsHub := websocket.NewHub()
	go wsHub.Run()
	log.Println("✅ WebSocket hub started")

	// Initialize HTTP router
	router := setupRouter(cfg, agentService, yaraService, alertService,
		eventService, taskService, threatIntelService, wsHub, quarantineHandler, analyticsHandler, authMiddleware, notificationService, configService)

	// Start background services only if databases are available
	log.Println("🔄 Starting background services...")
	if redisClient != nil {
		go agentService.StartHeartbeatMonitor()
		go alertService.StartProcessor()
		go eventService.StartProcessor()
		go taskService.StartProcessor()
		go performanceService.StartMonitoring(context.Background())
		log.Println("✅ Background services started")
	} else {
		log.Println("⚠️  Skipping background services (Redis not available)")
	}

	// Start HTTP server
	srv := &http.Server{
		Addr:         cfg.Server.Address,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("🌐 EDR Server listening on %s", cfg.Server.Address)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("❌ Server failed to start: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("🛑 Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("❌ Server forced to shutdown:", err)
	}

	log.Println("✅ Server exited")
}

func setupRouter(cfg *config.Config, agentService *services.AgentService,
	yaraService *services.YaraService, alertService *services.AlertService,
	eventService *services.EventService, taskService *services.TaskService,
	threatIntelService *services.ThreatIntelService, wsHub *websocket.Hub, quarantineHandler *api.QuarantineHandler, analyticsHandler *api.AnalyticsHandler, authMiddleware *middleware.AuthMiddleware, notificationService *services.NotificationService, configService *services.ConfigService) *gin.Engine {

	if cfg.Server.Mode == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// Middleware
	router.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	}))

	router.Use(gin.Recovery())

	// CORS configuration
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowAllOrigins = true
	corsConfig.AllowHeaders = []string{
		"Origin", "Content-Length", "Content-Type",
		"Authorization", "X-Agent-ID", "X-API-Key",
	}
	corsConfig.AllowMethods = []string{
		"GET", "POST", "PUT", "DELETE", "OPTIONS",
	}
	router.Use(cors.New(corsConfig))

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"timestamp": time.Now().Unix(),
			"version":   "1.0.0",
			"service":   "EDR Server",
			"uptime":    time.Since(startTime).Seconds(),
		})
	})

	// System info endpoint
	router.GET("/info", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"name":        "EDR Server",
			"version":     "1.0.0",
			"description": "Endpoint Detection and Response System",
			"author":      "EDR Team",
			"build_time":  time.Now().Format(time.RFC3339),
		})
	})

	// WebSocket endpoint for real-time updates
	router.GET("/ws", func(c *gin.Context) {
		websocket.HandleWebSocket(wsHub, c.Writer, c.Request)
	})

	// API routes
	apiRouter := router.Group("/api/v1")
	{
		// Apply rate limiting to all API routes
		apiRouter.Use(authMiddleware.RateLimit(100, time.Minute))

		// Agent management endpoints (agent authentication)
		agentRouter := apiRouter.Group("/agents")
		{
			agentHandler := api.NewAgentHandler(agentService, wsHub)

			// Agent self-service endpoints (used by agents)
			agentRouter.POST("/register", agentHandler.Register)            // No auth for registration
			agentRouter.GET("/check-by-mac", agentHandler.CheckExistsByMAC) // No auth for checking by MAC
			agentRouter.Use(authMiddleware.AgentAuth())                     // Apply auth to other agent endpoints
			agentRouter.POST("/heartbeat", agentHandler.Heartbeat)
			agentRouter.POST("/events", agentHandler.ReceiveEvents)
			agentRouter.GET("/:id/tasks", agentHandler.GetTasks)
			agentRouter.POST("/:id/tasks/:taskId/result", agentHandler.SubmitTaskResult)

			// Admin endpoints (used by dashboard)
			agentRouter.GET("", agentHandler.List)
			agentRouter.GET("/:id", agentHandler.Get)
			agentRouter.PUT("/:id", agentHandler.Update)
			agentRouter.DELETE("/:id", agentHandler.Delete)
			agentRouter.POST("/:id/tasks", agentHandler.CreateTask)
			agentRouter.GET("/:id/status", agentHandler.GetStatus)
		}

		// YARA Rules management
		yaraRouter := apiRouter.Group("/yara")
		yaraRouter.Use(authMiddleware.AdminAuth())
		yaraRouter.Use(authMiddleware.RBAC("admin"))
		{
			yaraHandler := api.NewYaraHandler(yaraService, wsHub)
			yaraRouter.GET("", yaraHandler.List)
			yaraRouter.POST("", yaraHandler.Create)
			yaraRouter.GET("/:id", yaraHandler.Get)
			yaraRouter.PUT("/:id", yaraHandler.Update)
			yaraRouter.DELETE("/:id", yaraHandler.Delete)
			yaraRouter.POST("/:id/deploy", yaraHandler.Deploy)
			yaraRouter.POST("/:id/compile", yaraHandler.Compile)
			yaraRouter.GET("/:id/deployments", yaraHandler.GetDeployments)
		}

		// Alert management
		alertRouter := apiRouter.Group("/alerts")
		alertRouter.Use(authMiddleware.AdminAuth())
		alertRouter.Use(authMiddleware.RBAC("admin"))
		{
			alertHandler := api.NewAlertHandler(alertService, wsHub)
			alertRouter.GET("", alertHandler.List)
			alertRouter.GET("/:id", alertHandler.Get)
			alertRouter.PUT("/:id", alertHandler.Update)
			alertRouter.DELETE("/:id", alertHandler.Delete)
			alertRouter.POST("/:id/resolve", alertHandler.Resolve)
			alertRouter.POST("/:id/false-positive", alertHandler.MarkFalsePositive)
			alertRouter.GET("/stats", alertHandler.GetStats)
			alertRouter.GET("/timeline", alertHandler.GetTimeline)
		}

		// Event querying and analysis
		eventRouter := apiRouter.Group("/events")
		eventRouter.Use(authMiddleware.AdminAuth())
		eventRouter.Use(authMiddleware.RBAC("admin"))
		{
			eventHandler := api.NewEventHandler(eventService)
			eventRouter.GET("", eventHandler.Query)
			eventRouter.GET("/stats", eventHandler.GetStats)
			eventRouter.GET("/timeline", eventHandler.GetTimeline)
			eventRouter.POST("/search", eventHandler.Search)
		}

		// Task management
		taskRouter := apiRouter.Group("/tasks")
		taskRouter.Use(authMiddleware.AdminAuth())
		taskRouter.Use(authMiddleware.RBAC("admin"))
		{
			taskHandler := api.NewTaskHandler(taskService, wsHub)
			taskRouter.GET("", taskHandler.List)
			taskRouter.GET("/:id", taskHandler.Get)
			taskRouter.POST("", taskHandler.Create)
			taskRouter.PUT("/:id", taskHandler.Update)
			taskRouter.DELETE("/:id", taskHandler.Delete)
			taskRouter.POST("/:id/cancel", taskHandler.Cancel)
		}

		// Threat Intelligence
		threatRouter := apiRouter.Group("/threat-intel")
		threatRouter.Use(authMiddleware.AdminAuth())
		threatRouter.Use(authMiddleware.RBAC("admin"))
		{
			threatHandler := api.NewThreatIntelHandler(threatIntelService)
			threatRouter.GET("", threatHandler.List)
			threatRouter.POST("", threatHandler.Create)
			threatRouter.GET("/:id", threatHandler.Get)
			threatRouter.PUT("/:id", threatHandler.Update)
			threatRouter.DELETE("/:id", threatHandler.Delete)
			threatRouter.GET("/lookup", threatHandler.IOCLookup)
			threatRouter.POST("/enrich-event", threatHandler.EnrichEvent)
			threatRouter.POST("/enrich-alert/:alertId", threatHandler.EnrichAlert)
			threatRouter.GET("/mitre-mapping", threatHandler.MITREMapping)
			threatRouter.POST("/bulk-enrichment", threatHandler.BulkEnrichment)
			threatRouter.GET("/stats", threatHandler.GetThreatStats)
			threatRouter.POST("/import", threatHandler.ImportIndicators)
			threatRouter.GET("/lookup/:type/:value", threatHandler.LookupIndicator)
		}

		// Notifications
		notificationRouter := apiRouter.Group("/notifications")
		notificationRouter.Use(authMiddleware.AdminAuth())
		notificationRouter.Use(authMiddleware.RBAC("admin"))
		{
			notificationHandler := api.NewNotificationHandler(notificationService)
			notificationRouter.GET("", notificationHandler.List)
			notificationRouter.POST("", notificationHandler.Create)
			notificationRouter.GET("/:id", notificationHandler.Get)
			notificationRouter.PUT("/:id", notificationHandler.Update)
			notificationRouter.DELETE("/:id", notificationHandler.Delete)
			notificationRouter.POST("/:id/test", notificationHandler.Test)
		}

		// System Configuration
		configRouter := apiRouter.Group("/config")
		configRouter.Use(authMiddleware.AdminAuth())
		configRouter.Use(authMiddleware.RBAC("admin"))
		{
			configHandler := api.NewConfigHandler(configService)
			configRouter.GET("", configHandler.List)
			configRouter.GET("/:category", configHandler.GetByCategory)
			configRouter.POST("", configHandler.Create)
			configRouter.PUT("/:category/:key", configHandler.Update)
			configRouter.DELETE("/:category/:key", configHandler.Delete)
		}

		// Dashboard endpoints
		dashboardRouter := apiRouter.Group("/dashboard")
		{
			dashboardHandler := api.NewDashboardHandler(agentService, alertService, eventService)
			dashboardRouter.GET("/overview", dashboardHandler.GetOverview)
			dashboardRouter.GET("/metrics", dashboardHandler.GetMetrics)
			dashboardRouter.GET("/recent-alerts", dashboardHandler.GetRecentAlerts)
			dashboardRouter.GET("/agent-status", dashboardHandler.GetAgentStatus)
			dashboardRouter.GET("/threat-trends", dashboardHandler.GetThreatTrends)
			dashboardRouter.GET("/performance", dashboardHandler.GetPerformance)
		}

		// System management
		systemRouter := apiRouter.Group("/system")
		{
			systemHandler := api.NewSystemHandler(agentService)
			systemRouter.GET("/config", systemHandler.GetConfig)
			systemRouter.PUT("/config", systemHandler.UpdateConfig)
			systemRouter.GET("/logs", systemHandler.GetLogs)
			systemRouter.POST("/backup", systemHandler.CreateBackup)
		}

		// Quarantine endpoints
		q := apiRouter.Group("/quarantine")
		{
			q.POST("/upload", quarantineHandler.UploadFile)
			q.GET("/files", quarantineHandler.ListFiles)
			q.GET("/:id", quarantineHandler.GetFile)
			q.POST("/:id/restore", quarantineHandler.RestoreFile)
			q.DELETE("/:id", quarantineHandler.DeleteFile)
		}

		// Public endpoints (no authentication required)
		publicRouter := apiRouter.Group("/public")
		{
			publicRouter.POST("/quarantine/upload", quarantineHandler.UploadFile)
		}

		// Analytics endpoints
		analyticsRouter := apiRouter.Group("/analytics")
		analyticsRouter.Use(authMiddleware.AdminAuth())
		analyticsRouter.Use(authMiddleware.RBAC("admin"))
		{
			analyticsRouter.GET("/correlation", analyticsHandler.EventCorrelation)
			analyticsRouter.GET("/anomalies/:agentId", analyticsHandler.AnomalyDetection)
			analyticsRouter.POST("/threat-hunting", analyticsHandler.ThreatHunting)
			analyticsRouter.GET("/dashboard", analyticsHandler.GetDashboardMetrics)
			analyticsRouter.GET("/performance", analyticsHandler.GetPerformanceMetrics)
			analyticsRouter.GET("/reports/:type", analyticsHandler.GenerateReport)
			analyticsRouter.GET("/anomaly-stats", analyticsHandler.GetAnomalyStats)
			analyticsRouter.GET("/threat-queries", analyticsHandler.GetThreatHuntQueries)
			analyticsRouter.POST("/threat-queries", analyticsHandler.SaveThreatHuntQuery)
			analyticsRouter.GET("/report-history", analyticsHandler.GetReportHistory)
		}
	}

	return router
}
