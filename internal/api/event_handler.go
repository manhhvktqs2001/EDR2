package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"edr-server/internal/services"

	"github.com/gin-gonic/gin"
)

type EventHandler struct {
	eventService *services.EventService
}

func NewEventHandler(eventService *services.EventService) *EventHandler {
	return &EventHandler{
		eventService: eventService,
	}
}

// Query handles event querying
func (h *EventHandler) Query(c *gin.Context) {
	agentID := c.Query("agent_id")
	eventType := c.Query("event_type")
	startTime := c.Query("start_time")
	endTime := c.Query("end_time")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))

	var start, end time.Time
	var err error

	if startTime != "" {
		start, err = time.Parse(time.RFC3339, startTime)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid start_time format"})
			return
		}
	} else {
		start = time.Now().Add(-24 * time.Hour) // Default to last 24 hours
	}

	if endTime != "" {
		end, err = time.Parse(time.RFC3339, endTime)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid end_time format"})
			return
		}
	} else {
		end = time.Now()
	}

	filters := map[string]interface{}{
		"agent_id":  agentID,
		"event_type": eventType,
		"start_time": start,
		"end_time":   end,
	}
	events, err := h.eventService.QueryEvents(filters, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"events":     events,
		"start_time": start,
		"end_time":   end,
		"count":      len(events),
	})
}

// GetStats returns event statistics
func (h *EventHandler) GetStats(c *gin.Context) {
	ctx := context.Background()
	stats, err := h.eventService.GetEventStats(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// GetTimeline returns event timeline
func (h *EventHandler) GetTimeline(c *gin.Context) {
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))

	timeline, err := h.eventService.GetEventTimeline(hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, timeline)
}

// Search performs advanced event searching
func (h *EventHandler) Search(c *gin.Context) {
	var req struct {
		Query     string            `json:"query"`
		AgentIDs  []string          `json:"agent_ids"`
		EventType string            `json:"event_type"`
		StartTime string            `json:"start_time"`
		EndTime   string            `json:"end_time"`
		Filters   map[string]string `json:"filters"`
		Limit     int               `json:"limit"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Limit == 0 {
		req.Limit = 100
	}

	var start, end time.Time
	var err error

	if req.StartTime != "" {
		start, err = time.Parse(time.RFC3339, req.StartTime)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid start_time format"})
			return
		}
	} else {
		start = time.Now().Add(-24 * time.Hour)
	}

	if req.EndTime != "" {
		end, err = time.Parse(time.RFC3339, req.EndTime)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid end_time format"})
			return
		}
	} else {
		end = time.Now()
	}

	filters := map[string]interface{}{
		"agent_ids":  req.AgentIDs,
		"event_type": req.EventType,
		"start_time": start,
		"end_time":   end,
		"filters":    req.Filters,
		"limit":      req.Limit,
	}
	events, err := h.eventService.SearchEvents(req.Query, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"events":     events,
		"query":      req.Query,
		"start_time": start,
		"end_time":   end,
		"count":      len(events),
	})
}
