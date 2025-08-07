package services

import (
	"context"
	"time"

	"edr-server/internal/models"
	"edr-server/internal/repositories"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
)

type EventService struct {
	influxClient influxdb2.Client
	redisClient  *redis.Client
	eventRepo    *repositories.EventRepository
	org          string
	bucket       string
}

func NewEventService(influxClient influxdb2.Client, redisClient *redis.Client) *EventService {
	return &EventService{
		influxClient: influxClient,
		redisClient:  redisClient,
		eventRepo:    repositories.NewEventRepository(nil), // Event repo doesn't need DB
		org:          "edr-org",
		bucket:       "events",
	}
}

// StoreEvent stores an event in InfluxDB
func (s *EventService) StoreEvent(event *models.Event) error {
	if s.influxClient == nil {
		return nil // Skip if InfluxDB not available
	}

	ctx := context.Background()
	writeAPI := s.influxClient.WriteAPIBlocking(s.org, s.bucket)

	// Create InfluxDB point
	point := influxdb2.NewPoint(
		"security_events",
		map[string]string{
			"agent_id":   event.AgentID,
			"event_type": event.EventType,
		},
		map[string]interface{}{
			"timestamp": event.Timestamp.Unix(),
			"data":      event.Data,
		},
		event.Timestamp,
	)

	writeAPI.WritePoint(ctx, point)
	return writeAPI.Flush(ctx)
}

// ProcessEvents processes events from agent and stores them in InfluxDB
func (s *EventService) ProcessEvents(agentID string, events []map[string]interface{}) error {
	for _, eventData := range events {
		// Extract event information
		eventType, _ := eventData["event_type"].(string)
		if eventType == "" {
			eventType = "unknown"
		}

		// Create event model
		event := &models.Event{
			AgentID:   agentID,
			EventType: eventType,
			Timestamp: time.Now(),
			Data:      eventData,
		}

		// Store event in InfluxDB
		if err := s.StoreEvent(event); err != nil {
			// Log error but continue processing other events
			continue
		}
	}

	return nil
}

// GetEventsByAgent retrieves events for a specific agent
func (s *EventService) GetEventsByAgent(agentID uuid.UUID, limit int) ([]models.Event, error) {
	return s.eventRepo.GetEventsByAgent(agentID, limit)
}

// GetEventsByTimeRange retrieves events within a time range
func (s *EventService) GetEventsByTimeRange(start, end time.Time, limit int) ([]models.Event, error) {
	return s.eventRepo.GetEventsByTimeRange(start, end, limit)
}

// GetEventStats returns event statistics
func (s *EventService) GetEventStats(ctx context.Context) (map[string]interface{}, error) {
	return s.eventRepo.GetEventStats(ctx)
}

// StartProcessor starts the event processor
func (s *EventService) StartProcessor() {
	// Implementation for event processing
	// This would typically involve processing events from various sources
}

// QueryEvents queries events with filters
func (s *EventService) QueryEvents(filters map[string]interface{}, limit int) ([]models.Event, error) {
	// Implementation for querying events
	return []models.Event{}, nil
}

// GetEventTimeline returns event timeline
func (s *EventService) GetEventTimeline(hours int) (map[string]interface{}, error) {
	// Implementation for event timeline
	return map[string]interface{}{}, nil
}

// SearchEvents searches events
func (s *EventService) SearchEvents(query string, filters map[string]interface{}) ([]models.Event, error) {
	// Implementation for searching events
	return []models.Event{}, nil
}

// GetPerformanceMetrics returns performance metrics
func (s *EventService) GetPerformanceMetrics() (map[string]interface{}, error) {
	// Implementation for performance metrics
	return map[string]interface{}{}, nil
} 