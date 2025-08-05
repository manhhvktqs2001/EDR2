package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"edr-server/internal/models"

	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"
	"github.com/google/uuid"
)

type ThreatIntelService struct {
	db    *gorm.DB
	redis *redis.Client
	// External TI APIs
	virusTotalAPIKey string
	abuseIPDBAPIKey  string
	urlhausAPIKey    string
}

func NewThreatIntelService(db *gorm.DB, redis *redis.Client) *ThreatIntelService {
	return &ThreatIntelService{
		db:    db,
		redis: redis,
		// Load API keys from config
		virusTotalAPIKey: "your-virustotal-api-key",
		abuseIPDBAPIKey:  "your-abuseipdb-api-key",
		urlhausAPIKey:    "your-urlhaus-api-key",
	}
}

// IOCLookup looks up indicators of compromise
func (s *ThreatIntelService) IOCLookup(ctx context.Context, indicatorType, indicatorValue string) (*models.ThreatIntelligence, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("ti:%s:%s", indicatorType, indicatorValue)
	if cached, err := s.redis.Get(ctx, cacheKey).Result(); err == nil {
		var ti models.ThreatIntelligence
		if err := json.Unmarshal([]byte(cached), &ti); err == nil {
			return &ti, nil
		}
	}

	// Lookup in local database
	var ti models.ThreatIntelligence
	if err := s.db.Where("indicator_type = ? AND indicator_value = ? AND is_active = ?", 
		indicatorType, indicatorValue, true).First(&ti).Error; err == nil {
		// Cache result
		if data, err := json.Marshal(ti); err == nil {
			s.redis.Set(ctx, cacheKey, data, time.Hour)
		}
		return &ti, nil
	}

	// External lookup
	externalTI, err := s.externalIOCLookup(indicatorType, indicatorValue)
	if err != nil {
		return nil, fmt.Errorf("external lookup failed: %w", err)
	}

	// Save to database
	if err := s.db.Create(externalTI).Error; err != nil {
		return nil, fmt.Errorf("failed to save TI: %w", err)
	}

	// Cache result
	if data, err := json.Marshal(externalTI); err == nil {
		s.redis.Set(ctx, cacheKey, data, time.Hour)
	}

	return externalTI, nil
}

// externalIOCLookup performs external threat intelligence lookup
func (s *ThreatIntelService) externalIOCLookup(indicatorType, indicatorValue string) (*models.ThreatIntelligence, error) {
	ti := &models.ThreatIntelligence{
		IndicatorType:  indicatorType,
		IndicatorValue: indicatorValue,
		Source:         "external",
		IsActive:       true,
		CreatedAt:      time.Now(),
	}

	switch indicatorType {
	case "hash":
		return s.lookupHash(indicatorValue, ti)
	case "domain":
		return s.lookupDomain(indicatorValue, ti)
	case "ip":
		return s.lookupIP(indicatorValue, ti)
	case "url":
		return s.lookupURL(indicatorValue, ti)
	default:
		return nil, fmt.Errorf("unsupported indicator type: %s", indicatorType)
	}
}

// lookupHash looks up file hash in external TI sources
func (s *ThreatIntelService) lookupHash(hash string, ti *models.ThreatIntelligence) (*models.ThreatIntelligence, error) {
	// VirusTotal lookup
	url := fmt.Sprintf("https://www.virustotal.com/vtapi/v2/file/report?apikey=%s&resource=%s", 
		s.virusTotalAPIKey, hash)
	
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var vtResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&vtResponse); err == nil {
		if positives, ok := vtResponse["positives"].(float64); ok {
			ti.Confidence = &[]int{int(positives)}[0]
			ti.Severity = s.calculateSeverity(positives)
		}
		if scans, ok := vtResponse["scans"].(map[string]interface{}); ok {
			var malwareFamilies []string
			for scanner, result := range scans {
				if resultMap, ok := result.(map[string]interface{}); ok {
					if detected, ok := resultMap["detected"].(bool); ok && detected {
						if result, ok := resultMap["result"].(string); ok {
							malwareFamilies = append(malwareFamilies, fmt.Sprintf("%s:%s", scanner, result))
						}
					}
				}
			}
			if len(malwareFamilies) > 0 {
				ti.MalwareFamily = strings.Join(malwareFamilies, "; ")
			}
		}
	}

	return ti, nil
}

// lookupDomain looks up domain in external TI sources
func (s *ThreatIntelService) lookupDomain(domain string, ti *models.ThreatIntelligence) (*models.ThreatIntelligence, error) {
	// URLhaus lookup
	url := fmt.Sprintf("https://urlhaus-api.abuse.ch/v1/host/", domain)
	
	payload := map[string]string{
		"host": domain,
	}
	
	jsonData, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var urlhausResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&urlhausResponse); err == nil {
		if queryStatus, ok := urlhausResponse["query_status"].(string); ok && queryStatus == "ok" {
			ti.Confidence = &[]int{80}[0]
			ti.Severity = 4
			ti.ThreatType = "malware_distribution"
		}
	}

	return ti, nil
}

// lookupIP looks up IP address in external TI sources
func (s *ThreatIntelService) lookupIP(ip string, ti *models.ThreatIntelligence) (*models.ThreatIntelligence, error) {
	// AbuseIPDB lookup
	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s", ip)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Key", s.abuseIPDBAPIKey)
	req.Header.Set("Accept", "application/json")
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var abuseResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&abuseResponse); err == nil {
		if data, ok := abuseResponse["data"].(map[string]interface{}); ok {
			if abuseConfidenceScore, ok := data["abuseConfidenceScore"].(float64); ok {
				ti.Confidence = &[]int{int(abuseConfidenceScore)}[0]
				ti.Severity = s.calculateSeverity(abuseConfidenceScore)
			}
		}
	}

	return ti, nil
}

// lookupURL looks up URL in external TI sources
func (s *ThreatIntelService) lookupURL(url string, ti *models.ThreatIntelligence) (*models.ThreatIntelligence, error) {
	// URLhaus lookup
	urlhausURL := "https://urlhaus-api.abuse.ch/v1/url/"
	
	payload := map[string]string{
		"url": url,
	}
	
	jsonData, _ := json.Marshal(payload)
	resp, err := http.Post(urlhausURL, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var urlhausResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&urlhausResponse); err == nil {
		if queryStatus, ok := urlhausResponse["query_status"].(string); ok && queryStatus == "ok" {
			ti.Confidence = &[]int{85}[0]
			ti.Severity = 4
			ti.ThreatType = "malware_distribution"
		}
	}

	return ti, nil
}

// calculateSeverity calculates severity based on confidence score
func (s *ThreatIntelService) calculateSeverity(confidence float64) int {
	switch {
	case confidence >= 80:
		return 5
	case confidence >= 60:
		return 4
	case confidence >= 40:
		return 3
	case confidence >= 20:
		return 2
	default:
		return 1
	}
}

// MITREMapping maps threats to MITRE ATT&CK framework
func (s *ThreatIntelService) MITREMapping(ctx context.Context, threatType, malwareFamily string) ([]string, []string, error) {
	// Load MITRE mappings from database or cache
	cacheKey := fmt.Sprintf("mitre:%s:%s", threatType, malwareFamily)
	if cached, err := s.redis.Get(ctx, cacheKey).Result(); err == nil {
		var mapping struct {
			Tactics   []string `json:"tactics"`
			Techniques []string `json:"techniques"`
		}
		if err := json.Unmarshal([]byte(cached), &mapping); err == nil {
			return mapping.Tactics, mapping.Techniques, nil
		}
	}

	// Default mappings based on threat type
	var tactics, techniques []string
	
	switch threatType {
	case "malware_distribution":
		tactics = []string{"Initial Access", "Execution", "Persistence"}
		techniques = []string{"T1071", "T1059", "T1053"}
	case "data_exfiltration":
		tactics = []string{"Collection", "Exfiltration"}
		techniques = []string{"T1005", "T1041"}
	case "privilege_escalation":
		tactics = []string{"Privilege Escalation", "Defense Evasion"}
		techniques = []string{"T1068", "T1055"}
	default:
		tactics = []string{"Initial Access"}
		techniques = []string{"T1071"}
	}

	// Cache mapping
	mapping := struct {
		Tactics   []string `json:"tactics"`
		Techniques []string `json:"techniques"`
	}{
		Tactics:   tactics,
		Techniques: techniques,
	}
	
	if data, err := json.Marshal(mapping); err == nil {
		s.redis.Set(ctx, cacheKey, data, 24*time.Hour)
	}

	return tactics, techniques, nil
}

// EnrichEvent enriches security event with threat intelligence
func (s *ThreatIntelService) EnrichEvent(ctx context.Context, event *models.Event) error {
	// Extract indicators from event data
	indicators := s.extractIndicators(event)
	
	for _, indicator := range indicators {
		ti, err := s.IOCLookup(ctx, indicator.Type, indicator.Value)
		if err != nil {
			continue // Skip if lookup fails
		}
		
		// Add threat intelligence to event
		if event.Data == nil {
			event.Data = make(map[string]interface{})
		}
		
		event.Data["threat_intelligence"] = map[string]interface{}{
			"indicator":     indicator.Value,
			"confidence":    ti.Confidence,
			"severity":      ti.Severity,
			"threat_type":   ti.ThreatType,
			"malware_family": ti.MalwareFamily,
		}
		
		// Add MITRE mapping
		tactics, techniques, err := s.MITREMapping(ctx, ti.ThreatType, ti.MalwareFamily)
		if err == nil {
			event.Data["mitre_tactics"] = tactics
			event.Data["mitre_techniques"] = techniques
		}
	}
	
	return nil
}

// EnrichAlert enriches security alert with threat intelligence
func (s *ThreatIntelService) EnrichAlert(ctx context.Context, alert *models.Alert) error {
	// Extract indicators from alert
	indicators := s.extractIndicatorsFromAlert(alert)
	
	for _, indicator := range indicators {
		ti, err := s.IOCLookup(ctx, indicator.Type, indicator.Value)
		if err != nil {
			continue
		}
		
		// Update alert with threat intelligence
		if alert.ThreatIndicators == nil {
			alert.ThreatIndicators = make(models.JSONB)
		}
		
		alert.ThreatIndicators[indicator.Value] = map[string]interface{}{
			"confidence":    ti.Confidence,
			"severity":      ti.Severity,
			"threat_type":   ti.ThreatType,
			"malware_family": ti.MalwareFamily,
		}
		
		// Add MITRE mapping
		tactics, techniques, err := s.MITREMapping(ctx, ti.ThreatType, ti.MalwareFamily)
		if err == nil {
			alert.MitreTactics = tactics
			alert.MitreTechniques = techniques
		}
	}
	
	return s.db.Save(alert).Error
}

// extractIndicators extracts indicators from event data
func (s *ThreatIntelService) extractIndicators(event *models.Event) []Indicator {
	var indicators []Indicator
	
	// Extract from event data
	if event.Data != nil {
		if hash, ok := event.Data["file_hash"].(string); ok && hash != "" {
			indicators = append(indicators, Indicator{Type: "hash", Value: hash})
		}
		if domain, ok := event.Data["domain"].(string); ok && domain != "" {
			indicators = append(indicators, Indicator{Type: "domain", Value: domain})
		}
		if ip, ok := event.Data["ip_address"].(string); ok && ip != "" {
			indicators = append(indicators, Indicator{Type: "ip", Value: ip})
		}
		if url, ok := event.Data["url"].(string); ok && url != "" {
			indicators = append(indicators, Indicator{Type: "url", Value: url})
		}
	}
	
	return indicators
}

// extractIndicatorsFromAlert extracts indicators from alert
func (s *ThreatIntelService) extractIndicatorsFromAlert(alert *models.Alert) []Indicator {
	var indicators []Indicator
	
	// Extract from alert fields
	if alert.FileHash != "" {
		indicators = append(indicators, Indicator{Type: "hash", Value: alert.FileHash})
	}
	
	// Extract from command line
	if alert.CommandLine != "" {
		// Simple extraction - in production, use regex patterns
		if strings.Contains(alert.CommandLine, "http://") || strings.Contains(alert.CommandLine, "https://") {
			// Extract URLs from command line
			// This is simplified - in production, use proper URL extraction
		}
	}
	
	return indicators
}

// Indicator represents an indicator of compromise
type Indicator struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// BulkEnrichment performs bulk enrichment of events/alerts
func (s *ThreatIntelService) BulkEnrichment(ctx context.Context, items []interface{}) error {
	for _, item := range items {
		switch v := item.(type) {
		case *models.Event:
			s.EnrichEvent(ctx, v)
		case *models.Alert:
			s.EnrichAlert(ctx, v)
		}
	}
	return nil
}

// GetThreatStats returns threat intelligence statistics
func (s *ThreatIntelService) GetThreatStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	
	// Get total indicators
	var totalCount int64
	s.db.Model(&models.ThreatIntelligence{}).Count(&totalCount)
	stats["total_indicators"] = totalCount
	
	// Get active indicators
	var activeCount int64
	s.db.Model(&models.ThreatIntelligence{}).Where("is_active = ?", true).Count(&activeCount)
	stats["active_indicators"] = activeCount
	
	// Get indicators by type
	var hashCount, domainCount, ipCount, urlCount int64
	s.db.Model(&models.ThreatIntelligence{}).Where("indicator_type = ?", "hash").Count(&hashCount)
	s.db.Model(&models.ThreatIntelligence{}).Where("indicator_type = ?", "domain").Count(&domainCount)
	s.db.Model(&models.ThreatIntelligence{}).Where("indicator_type = ?", "ip").Count(&ipCount)
	s.db.Model(&models.ThreatIntelligence{}).Where("indicator_type = ?", "url").Count(&urlCount)
	
	stats["indicators_by_type"] = map[string]int64{
		"hash":   hashCount,
		"domain": domainCount,
		"ip":     ipCount,
		"url":    urlCount,
	}
	
	// Get indicators by severity
	var highCount, mediumCount, lowCount int64
	s.db.Model(&models.ThreatIntelligence{}).Where("severity >= ?", 4).Count(&highCount)
	s.db.Model(&models.ThreatIntelligence{}).Where("severity = ?", 3).Count(&mediumCount)
	s.db.Model(&models.ThreatIntelligence{}).Where("severity <= ?", 2).Count(&lowCount)
	
	stats["indicators_by_severity"] = map[string]int64{
		"high":   highCount,
		"medium": mediumCount,
		"low":    lowCount,
	}
	
	return stats, nil
}

// ListIndicators returns list of threat intelligence indicators
func (s *ThreatIntelService) ListIndicators(page, limit int, indicatorType, threatType, isActive string) ([]models.ThreatIntelligence, int64, error) {
	var indicators []models.ThreatIntelligence
	var total int64
	
	query := s.db.Model(&models.ThreatIntelligence{})
	
	if indicatorType != "" {
		query = query.Where("indicator_type = ?", indicatorType)
	}
	if threatType != "" {
		query = query.Where("threat_type = ?", threatType)
	}
	if isActive != "" {
		query = query.Where("is_active = ?", isActive == "true")
	}
	
	// Get total count
	query.Count(&total)
	
	// Get paginated results
	offset := (page - 1) * limit
	err := query.Offset(offset).Limit(limit).Find(&indicators).Error
	
	return indicators, total, err
}

// GetIndicator returns a specific threat intelligence indicator
func (s *ThreatIntelService) GetIndicator(indicatorID uuid.UUID) (*models.ThreatIntelligence, error) {
	var indicator models.ThreatIntelligence
	err := s.db.Where("id = ?", indicatorID).First(&indicator).Error
	if err != nil {
		return nil, err
	}
	return &indicator, nil
}

// CreateIndicator creates a new threat intelligence indicator
func (s *ThreatIntelService) CreateIndicator(indicatorType, indicatorValue, threatType, malwareFamily string, confidence int, source, sourceURL, description string, severity int, tags []string) (*models.ThreatIntelligence, error) {
	indicator := &models.ThreatIntelligence{
		ID:             uuid.New(),
		IndicatorType:  indicatorType,
		IndicatorValue: indicatorValue,
		ThreatType:     threatType,
		MalwareFamily:  malwareFamily,
		Confidence:     &confidence,
		Source:         source,
		SourceURL:      sourceURL,
		Description:    description,
		Severity:       severity,
		Tags:           tags,
		IsActive:       true,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	
	err := s.db.Create(indicator).Error
	return indicator, err
}

// UpdateIndicator updates an existing threat intelligence indicator
func (s *ThreatIntelService) UpdateIndicator(indicatorID uuid.UUID, updates map[string]interface{}) error {
	updates["updated_at"] = time.Now()
	return s.db.Model(&models.ThreatIntelligence{}).Where("id = ?", indicatorID).Updates(updates).Error
}

// DeleteIndicator deletes a threat intelligence indicator
func (s *ThreatIntelService) DeleteIndicator(indicatorID uuid.UUID) error {
	return s.db.Where("id = ?", indicatorID).Delete(&models.ThreatIntelligence{}).Error
}

// GetDB returns the database instance
func (s *ThreatIntelService) GetDB() *gorm.DB {
	return s.db
}

// ImportIndicators imports indicators from external sources
func (s *ThreatIntelService) ImportIndicators(source, url, format, data string) (int, error) {
	// Implementation for importing indicators from external sources
	// This is a placeholder - in production, implement actual import logic
	return 0, nil
}

// LookupIndicator looks up indicators by type and value
func (s *ThreatIntelService) LookupIndicator(indicatorType, indicatorValue string) ([]models.ThreatIntelligence, error) {
	var indicators []models.ThreatIntelligence
	err := s.db.Where("indicator_type = ? AND indicator_value = ? AND is_active = ?", 
		indicatorType, indicatorValue, true).Find(&indicators).Error
	return indicators, err
}
