package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// JSONB type for PostgreSQL JSONB fields
type JSONB map[string]interface{}

func (j JSONB) Value() (driver.Value, error) {
	if len(j) == 0 {
		return "{}", nil
	}
	return json.Marshal(j)
}

func (j *JSONB) Scan(value interface{}) error {
	if value == nil {
		*j = make(JSONB)
		return nil
	}

	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, j)
	case string:
		return json.Unmarshal([]byte(v), j)
	default:
		return fmt.Errorf("cannot scan %T into JSONB", value)
	}
}

// Agent represents an EDR agent/endpoint
type Agent struct {
	ID                uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	Hostname          string         `json:"hostname" gorm:"not null;index"`
	IPAddress         string         `json:"ip_address" gorm:"type:inet"`
	MACAddress        string         `json:"mac_address" gorm:"size:17"`
	OSType            string         `json:"os_type" gorm:"not null;size:50;index"`
	OSVersion         string         `json:"os_version" gorm:"size:100"`
	Architecture      string         `json:"architecture" gorm:"size:20"`
	AgentVersion      string         `json:"agent_version" gorm:"size:50"`
	Status            string         `json:"status" gorm:"default:'offline';size:20;index"`
	LastSeen          time.Time      `json:"last_seen" gorm:"default:now();index"`
	FirstSeen         time.Time      `json:"first_seen" gorm:"default:now()"`
	HeartbeatInterval int            `json:"heartbeat_interval" gorm:"default:30"`
	Location          string         `json:"location" gorm:"size:255"`
	Department        string         `json:"department" gorm:"size:100"`
	Tags              pq.StringArray `json:"tags" gorm:"type:text[]"`
	Config            JSONB          `json:"config" gorm:"type:jsonb;default:'{}'"`
	Metadata          JSONB          `json:"metadata" gorm:"type:jsonb;default:'{}'"`
	APIKey            string         `json:"api_key" gorm:"size:64;unique;index"`
	IsActive          bool           `json:"is_active" gorm:"default:true;index"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`

	// Relationships
	Alerts           []Alert           `json:"alerts,omitempty" gorm:"foreignKey:AgentID"`
	Tasks            []AgentTask       `json:"tasks,omitempty" gorm:"foreignKey:AgentID"`
	QuarantinedFiles []QuarantinedFile `json:"quarantined_files,omitempty" gorm:"foreignKey:AgentID"`
	RuleDeployments  []RuleDeployment  `json:"rule_deployments,omitempty" gorm:"foreignKey:AgentID"`
}

// YaraRule represents a YARA detection rule
type YaraRule struct {
	ID          uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	Name        string         `json:"name" gorm:"not null;unique;index"`
	Content     string         `json:"content" gorm:"not null;type:text"`
	Description string         `json:"description" gorm:"type:text"`
	Author      string         `json:"author" gorm:"size:255"`
	Reference   string         `json:"reference" gorm:"size:500"`
	Version     int            `json:"version" gorm:"default:1"`
	Severity    int            `json:"severity" gorm:"default:1;check:severity >= 1 AND severity <= 5;index"`
	Category    string         `json:"category" gorm:"size:100;index"`
	Subcategory string         `json:"subcategory" gorm:"size:100"`
	Tags        pq.StringArray `json:"tags" gorm:"type:text[]"`
	Platform    string         `json:"platform" gorm:"size:50;check:platform IN ('Windows', 'Linux', 'macOS', 'All')"`
	IsActive    bool           `json:"is_active" gorm:"default:true;index"`
	IsCompiled  bool           `json:"is_compiled" gorm:"default:false"`
	CompiledAt  *time.Time     `json:"compiled_at"`
	FileHash    string         `json:"file_hash" gorm:"size:64"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`

	// Relationships
	Alerts      []Alert          `json:"alerts,omitempty" gorm:"foreignKey:RuleID"`
	Deployments []RuleDeployment `json:"deployments,omitempty" gorm:"foreignKey:RuleID"`
}

// RuleDeployment tracks YARA rule deployment to agents
type RuleDeployment struct {
	ID             uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	RuleID         uuid.UUID  `json:"rule_id" gorm:"not null;index"`
	AgentID        uuid.UUID  `json:"agent_id" gorm:"not null;index"`
	Status         string     `json:"status" gorm:"default:'pending';size:20;check:status IN ('pending', 'deployed', 'failed', 'outdated')"`
	DeployedAt     *time.Time `json:"deployed_at"`
	ErrorMessage   string     `json:"error_message" gorm:"type:text"`
	DeploymentHash string     `json:"deployment_hash" gorm:"size:64"`
	CreatedAt      time.Time  `json:"created_at"`

	// Relationships
	Rule  YaraRule `json:"rule,omitempty" gorm:"foreignKey:RuleID"`
	Agent Agent    `json:"agent,omitempty" gorm:"foreignKey:AgentID"`
}

// Alert represents a security alert
type Alert struct {
	ID               uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	AgentID          uuid.UUID      `json:"agent_id" gorm:"not null;index"`
	RuleID           *uuid.UUID     `json:"rule_id" gorm:"index"`
	EventID          string         `json:"event_id" gorm:"size:100;index"`
	Severity         int            `json:"severity" gorm:"not null;check:severity >= 1 AND severity <= 5;index"`
	Status           string         `json:"status" gorm:"default:'new';size:20;index;check:status IN ('new', 'investigating', 'resolved', 'false_positive')"`
	Title            string         `json:"title" gorm:"not null;size:500"`
	Description      string         `json:"description" gorm:"type:text"`
	FilePath         string         `json:"file_path" gorm:"type:text"`
	FileName         string         `json:"file_name" gorm:"size:255;index"`
	FileHash         string         `json:"file_hash" gorm:"size:64;index"`
	FileSize         *int64         `json:"file_size"`
	ProcessName      string         `json:"process_name" gorm:"size:255;index"`
	ProcessID        *int           `json:"process_id"`
	CommandLine      string         `json:"command_line" gorm:"type:text"`
	Username         string         `json:"username" gorm:"size:255;index"`
	DetectionTime    time.Time      `json:"detection_time" gorm:"not null;index"`
	FirstSeen        time.Time      `json:"first_seen" gorm:"default:now()"`
	LastSeen         time.Time      `json:"last_seen" gorm:"default:now()"`
	EventCount       int            `json:"event_count" gorm:"default:1"`
	ConfidenceScore  float64        `json:"confidence_score" gorm:"type:decimal(3,2);default:0.50"`
	ThreatIndicators JSONB          `json:"threat_indicators" gorm:"type:jsonb;default:'[]'"`
	MitreTactics     pq.StringArray `json:"mitre_tactics" gorm:"type:text[]"`
	MitreTechniques  pq.StringArray `json:"mitre_techniques" gorm:"type:text[]"`
	RemediationSteps string         `json:"remediation_steps" gorm:"type:text"`
	AnalystNotes     string         `json:"analyst_notes" gorm:"type:text"`
	Metadata         JSONB          `json:"metadata" gorm:"type:jsonb;default:'{}'"`
	CreatedAt        time.Time      `json:"created_at" gorm:"index"`
	UpdatedAt        time.Time      `json:"updated_at"`

	// Relationships
	Agent       Agent             `json:"agent,omitempty" gorm:"foreignKey:AgentID"`
	Rule        *YaraRule         `json:"rule,omitempty" gorm:"foreignKey:RuleID"`
	History     []AlertHistory    `json:"history,omitempty" gorm:"foreignKey:AlertID"`
	Quarantined []QuarantinedFile `json:"quarantined_files,omitempty" gorm:"foreignKey:AlertID"`
}

// AlertHistory tracks changes to alerts
type AlertHistory struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	AlertID   uuid.UUID `json:"alert_id" gorm:"not null;index"`
	Action    string    `json:"action" gorm:"not null;size:50"`
	OldValue  string    `json:"old_value" gorm:"type:text"`
	NewValue  string    `json:"new_value" gorm:"type:text"`
	Notes     string    `json:"notes" gorm:"type:text"`
	ChangedBy string    `json:"changed_by" gorm:"size:255"`
	ChangedAt time.Time `json:"changed_at" gorm:"default:now()"`

	// Relationships
	Alert Alert `json:"alert,omitempty" gorm:"foreignKey:AlertID"`
}

// Whitelist represents allowed items that should not trigger alerts
type Whitelist struct {
	ID          uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	Type        string     `json:"type" gorm:"not null;size:20;check:type IN ('file_hash', 'file_path', 'process_name', 'domain', 'ip_address');index"`
	Value       string     `json:"value" gorm:"not null;type:text;index"`
	Description string     `json:"description" gorm:"type:text"`
	Reason      string     `json:"reason" gorm:"size:255"`
	IsActive    bool       `json:"is_active" gorm:"default:true;index"`
	ExpiresAt   *time.Time `json:"expires_at"`
	CreatedBy   string     `json:"created_by" gorm:"size:255"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// QuarantinedFile represents files that have been quarantined
type QuarantinedFile struct {
	ID               uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	AgentID          uuid.UUID  `json:"agent_id" gorm:"not null;index"`
	AlertID          *uuid.UUID `json:"alert_id" gorm:"index"`
	OriginalPath     string     `json:"original_path" gorm:"not null;type:text"`
	QuarantinePath   string     `json:"quarantine_path" gorm:"not null;type:text"`
	FileName         string     `json:"file_name" gorm:"size:255;index"`
	FileHash         string     `json:"file_hash" gorm:"not null;size:64;index"`
	FileSize         *int64     `json:"file_size"`
	FileType         string     `json:"file_type" gorm:"size:50"`
	QuarantineReason string     `json:"quarantine_reason" gorm:"type:text"`
	Status           string     `json:"status" gorm:"default:'quarantined';size:20;check:status IN ('quarantined', 'restored', 'deleted')"`
	QuarantinedAt    time.Time  `json:"quarantined_at" gorm:"default:now()"`
	RestoredAt       *time.Time `json:"restored_at"`
	DeletedAt        *time.Time `json:"deleted_at"`
	AnalysisResult   JSONB      `json:"analysis_result" gorm:"type:jsonb;default:'{}'"`
	Metadata         JSONB      `json:"metadata" gorm:"type:jsonb;default:'{}'"`

	// Relationships
	Agent Agent  `json:"agent,omitempty" gorm:"foreignKey:AgentID"`
	Alert *Alert `json:"alert,omitempty" gorm:"foreignKey:AlertID"`
}

// ThreatIntelligence represents threat intelligence indicators
type ThreatIntelligence struct {
	ID             uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	IndicatorType  string         `json:"indicator_type" gorm:"not null;size:20;check:indicator_type IN ('hash', 'domain', 'ip', 'url', 'email');index"`
	IndicatorValue string         `json:"indicator_value" gorm:"not null;type:text;index"`
	ThreatType     string         `json:"threat_type" gorm:"size:50"`
	MalwareFamily  string         `json:"malware_family" gorm:"size:100"`
	Confidence     *int           `json:"confidence" gorm:"check:confidence >= 1 AND confidence <= 100"`
	Source         string         `json:"source" gorm:"not null;size:100;index"`
	SourceURL      string         `json:"source_url" gorm:"size:500"`
	Description    string         `json:"description" gorm:"type:text"`
	FirstSeen      *time.Time     `json:"first_seen"`
	LastSeen       *time.Time     `json:"last_seen"`
	IsActive       bool           `json:"is_active" gorm:"default:true;index"`
	Severity       int            `json:"severity" gorm:"default:3;check:severity >= 1 AND severity <= 5;index"`
	Tags           pq.StringArray `json:"tags" gorm:"type:text[]"`
	Attributes     JSONB          `json:"attributes" gorm:"type:jsonb;default:'{}'"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

// AgentGroup represents groups of agents for management
type AgentGroup struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	Name        string    `json:"name" gorm:"not null;unique;size:255"`
	Description string    `json:"description" gorm:"type:text"`
	GroupType   string    `json:"group_type" gorm:"default:'custom';size:50;check:group_type IN ('default', 'custom', 'auto')"`
	Rules       JSONB     `json:"rules" gorm:"type:jsonb;default:'{}'"`
	Config      JSONB     `json:"config" gorm:"type:jsonb;default:'{}'"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	// Many-to-many relationship with agents
	Agents []Agent `json:"agents,omitempty" gorm:"many2many:agent_group_members;"`
}

// AgentTask represents tasks sent to agents
type AgentTask struct {
	ID             uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	AgentID        uuid.UUID  `json:"agent_id" gorm:"not null;index"`
	TaskType       string     `json:"task_type" gorm:"not null;size:50;check:task_type IN ('scan_file', 'update_rules', 'collect_logs', 'quarantine_file', 'kill_process', 'isolate_network');index"`
	Parameters     JSONB      `json:"parameters" gorm:"type:jsonb;default:'{}'"`
	Status         string     `json:"status" gorm:"default:'pending';size:20;check:status IN ('pending', 'sent', 'completed', 'failed', 'timeout', 'cancelled');index"`
	Priority       int        `json:"priority" gorm:"default:5;check:priority >= 1 AND priority <= 10"`
	TimeoutSeconds int        `json:"timeout_seconds" gorm:"default:300"`
	CreatedBy      string     `json:"created_by" gorm:"size:255"`
	CreatedAt      time.Time  `json:"created_at" gorm:"index"`
	SentAt         *time.Time `json:"sent_at"`
	CompletedAt    *time.Time `json:"completed_at"`
	Result         JSONB      `json:"result" gorm:"type:jsonb;default:'{}'"`
	ErrorMessage   string     `json:"error_message" gorm:"type:text"`
	Progress       int        `json:"progress" gorm:"default:0;check:progress >= 0 AND progress <= 100"`

	// Relationships
	Agent Agent `json:"agent,omitempty" gorm:"foreignKey:AgentID"`
}

// SystemConfig represents system configuration key-value pairs
type SystemConfig struct {
	ID          int       `json:"id" gorm:"primary_key;auto_increment"`
	Category    string    `json:"category" gorm:"not null;size:100;index"`
	Key         string    `json:"key" gorm:"not null;size:100"`
	Value       string    `json:"value" gorm:"not null;type:text"`
	Description string    `json:"description" gorm:"type:text"`
	DataType    string    `json:"data_type" gorm:"default:'string';size:20;check:data_type IN ('string', 'integer', 'boolean', 'json')"`
	IsEncrypted bool      `json:"is_encrypted" gorm:"default:false"`
	IsReadonly  bool      `json:"is_readonly" gorm:"default:false"`
	UpdatedBy   string    `json:"updated_by" gorm:"size:255"`
	UpdatedAt   time.Time `json:"updated_at" gorm:"default:now()"`
}

// NotificationSetting represents notification configuration
type NotificationSetting struct {
	ID             uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	Name           string         `json:"name" gorm:"not null;size:255"`
	Type           string         `json:"type" gorm:"not null;size:20;check:type IN ('email', 'webhook', 'sms', 'slack', 'teams')"`
	Config         JSONB          `json:"config" gorm:"not null;type:jsonb"`
	Triggers       pq.StringArray `json:"triggers" gorm:"not null;type:text[]"`
	SeverityFilter pq.Int64Array  `json:"severity_filter" gorm:"type:integer[];default:'{1,2,3,4,5}'"`
	IsActive       bool           `json:"is_active" gorm:"default:true"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

// AuditLog represents system audit log entries
type AuditLog struct {
	ID           uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	Action       string     `json:"action" gorm:"not null;size:100;index"`
	ResourceType string     `json:"resource_type" gorm:"size:50;index"`
	ResourceID   *uuid.UUID `json:"resource_id" gorm:"index"`
	ResourceName string     `json:"resource_name" gorm:"size:255"`
	Description  string     `json:"description" gorm:"type:text"`
	UserID       string     `json:"user_id" gorm:"size:255;index"`
	IPAddress    string     `json:"ip_address" gorm:"type:inet"`
	UserAgent    string     `json:"user_agent" gorm:"type:text"`
	Success      bool       `json:"success" gorm:"default:true;index"`
	ErrorMessage string     `json:"error_message" gorm:"type:text"`
	Metadata     JSONB      `json:"metadata" gorm:"type:jsonb;default:'{}'"`
	Timestamp    time.Time  `json:"timestamp" gorm:"default:now();index"`
}

// Custom table names
func (Agent) TableName() string               { return "agents" }
func (YaraRule) TableName() string            { return "yara_rules" }
func (RuleDeployment) TableName() string      { return "rule_deployments" }
func (Alert) TableName() string               { return "alerts" }
func (AlertHistory) TableName() string        { return "alert_history" }
func (Whitelist) TableName() string           { return "whitelist" }
func (QuarantinedFile) TableName() string     { return "quarantined_files" }
func (ThreatIntelligence) TableName() string  { return "threat_intelligence" }
func (AgentGroup) TableName() string          { return "agent_groups" }
func (AgentTask) TableName() string           { return "agent_tasks" }
func (SystemConfig) TableName() string        { return "system_config" }
func (NotificationSetting) TableName() string { return "notification_settings" }
func (AuditLog) TableName() string            { return "audit_logs" }
func (EventStatistics) TableName() string     { return "event_statistics" }
func (AgentGroupMember) TableName() string    { return "agent_group_members" }

// BeforeCreate hooks
func (a *Agent) BeforeCreate(tx *gorm.DB) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	return nil
}

func (yr *YaraRule) BeforeCreate(tx *gorm.DB) error {
	if yr.ID == uuid.Nil {
		yr.ID = uuid.New()
	}
	return nil
}

func (al *Alert) BeforeCreate(tx *gorm.DB) error {
	if al.ID == uuid.Nil {
		al.ID = uuid.New()
	}
	return nil
}

// Helper methods for status checks
func (a *Agent) IsOnline() bool {
	// Agent is online if status is "online" and last seen within 2 minutes
	return a.Status == "online" && time.Since(a.LastSeen) < 2*time.Minute
}

func (a *Agent) IsOffline() bool {
	// Agent is offline if status is "offline" or last seen more than 2 minutes ago
	return a.Status == "offline" || time.Since(a.LastSeen) > 2*time.Minute
}

func (al *Alert) IsNew() bool {
	return al.Status == "new"
}

func (al *Alert) IsResolved() bool {
	return al.Status == "resolved"
}

func (al *Alert) IsCritical() bool {
	return al.Severity >= 4
}

func (at *AgentTask) IsPending() bool {
	return at.Status == "pending"
}

func (at *AgentTask) IsCompleted() bool {
	return at.Status == "completed"
}

func (at *AgentTask) HasFailed() bool {
	return at.Status == "failed"
}

// Event structures for InfluxDB (not GORM models)
type Event struct {
	AgentID   string                 `json:"agent_id"`
	EventType string                 `json:"event_type"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	Tags      map[string]string      `json:"tags"`
	Fields    map[string]interface{} `json:"fields"`
}

type FileEvent struct {
	Path        string    `json:"path"`
	Name        string    `json:"name"`
	Hash        string    `json:"hash"`
	Size        int64     `json:"size"`
	Action      string    `json:"action"` // created, modified, deleted, accessed
	ProcessName string    `json:"process_name"`
	Username    string    `json:"username"`
	Timestamp   time.Time `json:"timestamp"`
}

type ProcessEvent struct {
	PID         int       `json:"pid"`
	PPID        int       `json:"ppid"`
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	CommandLine string    `json:"command_line"`
	Username    string    `json:"username"`
	Action      string    `json:"action"` // start, stop, connect
	Timestamp   time.Time `json:"timestamp"`
}

type NetworkEvent struct {
	Protocol      string    `json:"protocol"`
	LocalIP       string    `json:"local_ip"`
	LocalPort     int       `json:"local_port"`
	RemoteIP      string    `json:"remote_ip"`
	RemotePort    int       `json:"remote_port"`
	Direction     string    `json:"direction"` // inbound, outbound
	ProcessName   string    `json:"process_name"`
	Username      string    `json:"username"`
	BytesSent     int64     `json:"bytes_sent"`
	BytesReceived int64     `json:"bytes_received"`
	Timestamp     time.Time `json:"timestamp"`
}

// Anomaly represents detected anomalous behavior
type Anomaly struct {
	ID          uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	AgentID     string     `json:"agent_id" gorm:"not null;index"`
	Type        string     `json:"type" gorm:"not null;size:50"`
	EventType   string     `json:"event_type" gorm:"size:100"`
	ProcessName string     `json:"process_name" gorm:"size:255"`
	Count       int        `json:"count"`
	Severity    string     `json:"severity" gorm:"size:20"`
	Description string     `json:"description" gorm:"type:text"`
	DetectedAt  time.Time  `json:"detected_at" gorm:"default:now()"`
	IsResolved  bool       `json:"is_resolved" gorm:"default:false"`
	ResolvedAt  *time.Time `json:"resolved_at"`
	Metadata    JSONB      `json:"metadata" gorm:"type:jsonb;default:'{}'"`
}

// ThreatHuntQuery represents a threat hunting query
type ThreatHuntQuery struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	Name        string    `json:"name" gorm:"not null;size:255"`
	Description string    `json:"description" gorm:"type:text"`
	AgentID     string    `json:"agent_id" gorm:"index"`
	EventType   string    `json:"event_type" gorm:"size:100"`
	ProcessName string    `json:"process_name" gorm:"size:255"`
	TimeRange   string    `json:"time_range" gorm:"size:50"`
	Query       string    `json:"query" gorm:"type:text"`
	CreatedBy   string    `json:"created_by" gorm:"size:255"`
	CreatedAt   time.Time `json:"created_at" gorm:"default:now()"`
	Status      string    `json:"status" gorm:"default:'pending';size:20"`
	Results     JSONB     `json:"results" gorm:"type:jsonb;default:'[]'"`
}

// EventStatistics represents event statistics from InfluxDB
type EventStatistics struct {
	ID              uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	AgentID         uuid.UUID `json:"agent_id" gorm:"not null;index"`
	Date            time.Time `json:"date" gorm:"not null;index"`
	EventType       string    `json:"event_type" gorm:"not null;size:50"`
	EventCount      int       `json:"event_count" gorm:"default:0"`
	FileEvents      int       `json:"file_events" gorm:"default:0"`
	ProcessEvents   int       `json:"process_events" gorm:"default:0"`
	NetworkEvents   int       `json:"network_events" gorm:"default:0"`
	RegistryEvents  int       `json:"registry_events" gorm:"default:0"`
	MaliciousEvents int       `json:"malicious_events" gorm:"default:0"`
	CreatedAt       time.Time `json:"created_at" gorm:"default:now()"`

	// Relationships
	Agent Agent `json:"agent,omitempty" gorm:"foreignKey:AgentID"`
}

// AgentGroupMember represents many-to-many relationship between agents and groups
type AgentGroupMember struct {
	AgentID  uuid.UUID `json:"agent_id" gorm:"not null;primary_key"`
	GroupID  uuid.UUID `json:"group_id" gorm:"not null;primary_key"`
	JoinedAt time.Time `json:"joined_at" gorm:"default:now()"`

	// Relationships
	Agent Agent      `json:"agent,omitempty" gorm:"foreignKey:AgentID"`
	Group AgentGroup `json:"group,omitempty" gorm:"foreignKey:GroupID"`
}

// ThreatHuntResult represents a threat hunting result
type ThreatHuntResult struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	QueryID     uuid.UUID `json:"query_id" gorm:"not null;index"`
	AgentID     string    `json:"agent_id" gorm:"not null;index"`
	EventType   string    `json:"event_type" gorm:"size:100"`
	Timestamp   time.Time `json:"timestamp"`
	Confidence  float64   `json:"confidence" gorm:"type:decimal(3,2)"`
	Severity    string    `json:"severity" gorm:"size:20"`
	Description string    `json:"description" gorm:"type:text"`
	Data        JSONB     `json:"data" gorm:"type:jsonb;default:'{}'"`
	CreatedAt   time.Time `json:"created_at" gorm:"default:now()"`
}

// DashboardMetrics represents dashboard metrics
type DashboardMetrics struct {
	Timestamp     time.Time `json:"timestamp"`
	AgentCount    int       `json:"agent_count"`
	OnlineAgents  int       `json:"online_agents"`
	NewAlerts     int       `json:"new_alerts"`
	EventsPerHour int       `json:"events_per_hour"`
	ActiveThreats int       `json:"active_threats"`
	CPUUsage      float64   `json:"cpu_usage"`
	MemoryUsage   float64   `json:"memory_usage"`
	DiskUsage     float64   `json:"disk_usage"`
}

// PerformanceMetrics represents performance metrics
type PerformanceMetrics struct {
	Timestamp        time.Time                   `json:"timestamp"`
	TimeRange        time.Duration               `json:"time_range"`
	AgentPerformance map[string]AgentPerformance `json:"agent_performance"`
	TotalCPUUsage    float64                     `json:"total_cpu_usage"`
	TotalMemoryUsage float64                     `json:"total_memory_usage"`
	AverageLatency   float64                     `json:"average_latency"`
}

// AgentPerformance represents agent performance data
type AgentPerformance struct {
	AgentID      string    `json:"agent_id"`
	CPUUsage     float64   `json:"cpu_usage"`
	MemoryUsage  float64   `json:"memory_usage"`
	DiskUsage    float64   `json:"disk_usage"`
	NetworkUsage float64   `json:"network_usage"`
	Latency      float64   `json:"latency"`
	Timestamp    time.Time `json:"timestamp"`
}

// SecurityReport represents a security report
type SecurityReport struct {
	ID          uuid.UUID              `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	Type        string                 `json:"type" gorm:"not null;size:50"`
	Title       string                 `json:"title" gorm:"size:255"`
	Description string                 `json:"description" gorm:"type:text"`
	GeneratedAt time.Time              `json:"generated_at"`
	TimeRange   time.Duration          `json:"time_range"`
	Data        map[string]interface{} `json:"data"`
	CreatedBy   string                 `json:"created_by" gorm:"size:255"`
	IsScheduled bool                   `json:"is_scheduled" gorm:"default:false"`
	Schedule    string                 `json:"schedule" gorm:"size:100"`
	LastRun     *time.Time             `json:"last_run"`
	NextRun     *time.Time             `json:"next_run"`
	Status      string                 `json:"status" gorm:"default:'active';size:20"`
	CreatedAt   time.Time              `json:"created_at" gorm:"default:now()"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// SystemMetrics represents comprehensive system metrics
type SystemMetrics struct {
	Timestamp          time.Time          `json:"timestamp"`
	DatabaseMetrics    DatabaseMetrics    `json:"database_metrics"`
	PerformanceMetrics PerformanceMetrics `json:"performance_metrics"`
	SystemHealth       SystemHealth       `json:"system_health"`
}

// DatabaseMetrics represents database performance metrics
type DatabaseMetrics struct {
	AlertCount  int64   `json:"alert_count"`
	AgentCount  int64   `json:"agent_count"`
	EventCount  int64   `json:"event_count"`
	QueryTime   float64 `json:"query_time"`
	Connections int     `json:"connections"`
}

// SystemHealth represents system health status
type SystemHealth struct {
	Timestamp      time.Time `json:"timestamp"`
	Status         string    `json:"status"`
	DatabaseStatus string    `json:"database_status"`
	RedisStatus    string    `json:"redis_status"`
	InfluxDBStatus string    `json:"influxdb_status"`
	MinIOStatus    string    `json:"minio_status"`
	Uptime         float64   `json:"uptime"`
	MemoryUsage    float64   `json:"memory_usage"`
	CPUUsage       float64   `json:"cpu_usage"`
	DiskUsage      float64   `json:"disk_usage"`
}
