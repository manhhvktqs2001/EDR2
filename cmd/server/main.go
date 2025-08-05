package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"edr-server/internal/api"
	"edr-server/internal/config"
	"edr-server/internal/database"
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

func main() {
	log.Println("🚀 Starting EDR Server...")

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

	log.Println("✅ Services initialized")

	// Initialize WebSocket hub
	wsHub := websocket.NewHub()
	go wsHub.Run()
	log.Println("✅ WebSocket hub started")

	// Initialize HTTP router
	router := setupRouter(cfg, agentService, yaraService, alertService,
		eventService, taskService, threatIntelService, wsHub)

	// Start background services only if databases are available
	log.Println("🔄 Starting background services...")
	if redisClient != nil {
		go agentService.StartHeartbeatMonitor()
		go alertService.StartProcessor()
		go eventService.StartProcessor()
		go taskService.StartProcessor()
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
	threatIntelService *services.ThreatIntelService, wsHub *websocket.Hub) *gin.Engine {

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
		// Agent management endpoints
		agentRouter := apiRouter.Group("/agents")
		{
			agentHandler := api.NewAgentHandler(agentService, wsHub)

			// Agent self-service endpoints (used by agents)
			agentRouter.POST("/register", agentHandler.Register)
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
		{
			eventHandler := api.NewEventHandler(eventService)
			eventRouter.GET("", eventHandler.Query)
			eventRouter.GET("/stats", eventHandler.GetStats)
			eventRouter.GET("/timeline", eventHandler.GetTimeline)
			eventRouter.POST("/search", eventHandler.Search)
		}

		// Task management
		taskRouter := apiRouter.Group("/tasks")
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
		{
			threatHandler := api.NewThreatIntelHandler(threatIntelService)
			threatRouter.GET("", threatHandler.List)
			threatRouter.POST("", threatHandler.Create)
			threatRouter.GET("/:id", threatHandler.Get)
			threatRouter.PUT("/:id", threatHandler.Update)
			threatRouter.DELETE("/:id", threatHandler.Delete)
			threatRouter.POST("/import", threatHandler.Import)
			threatRouter.GET("/lookup/:type/:value", threatHandler.Lookup)
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
	}

	return router
}
