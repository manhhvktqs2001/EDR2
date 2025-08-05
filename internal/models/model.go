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
	ID           uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	Name         string         `json:"name" gorm:"not null;unique;index"`
	Content      string         `json:"content" gorm:"not null;type:text"`
	Description  string         `json:"description" gorm:"type:text"`
	Author       string         `json:"author" gorm:"size:255"`
	Reference    string         `json:"reference" gorm:"size:500"`
	Version      int            `json:"version" gorm:"default:1"`
	Severity     int            `json:"severity" gorm:"default:1;check:severity >= 1 AND severity <= 5;index"`
	Category     string         `json:"category" gorm:"size:100;index"`
	Subcategory  string         `json:"subcategory" gorm:"size:100"`
	Tags         pq.StringArray `json:"tags" gorm:"type:text[]"`
	Platform     string         `json:"platform" gorm:"size:50;check:platform IN ('Windows', 'Linux', 'macOS', 'All')"`
	IsActive     bool           `json:"is_active" gorm:"default:true;index"`
	IsCompiled   bool           `json:"is_compiled" gorm:"default:false"`
	CompiledAt   *time.Time     `json:"compiled_at"`
	FileHash     string         `json:"file_hash" gorm:"size:64"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`

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
	ID                uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	AgentID           uuid.UUID      `json:"agent_id" gorm:"not null;index"`
	RuleID            *uuid.UUID     `json:"rule_id" gorm:"index"`
	EventID           string         `json:"event_id" gorm:"size:100;index"`
	Severity          int            `json:"severity" gorm:"not null;check:severity >= 1 AND severity <= 5;index"`
	Status            string         `json:"status" gorm:"default:'new';size:20;index;check:status IN ('new', 'investigating', 'resolved', 'false_positive')"`
	Title             string         `json:"title" gorm:"not null;size:500"`
	Description       string         `json:"description" gorm:"type:text"`
	FilePath          string         `json:"file_path" gorm:"type:text"`
	FileName          string         `json:"file_name" gorm:"size:255;index"`
	FileHash          string         `json:"file_hash" gorm:"size:64;index"`
	FileSize          *int64         `json:"file_size"`
	ProcessName       string         `json:"process_name" gorm:"size:255;index"`
	ProcessID         *int           `json:"process_id"`
	CommandLine       string         `json:"command_line" gorm:"type:text"`
	Username          string         `json:"username" gorm:"size:255;index"`
	DetectionTime     time.Time      `json:"detection_time" gorm:"not null;index"`
	FirstSeen         time.Time      `json:"first_seen" gorm:"default:now()"`
	LastSeen          time.Time      `json:"last_seen" gorm:"default:now()"`
	EventCount        int            `json:"event_count" gorm:"default:1"`
	ConfidenceScore   float64        `json:"confidence_score" gorm:"type:decimal(3,2);default:0.50"`
	ThreatIndicators  JSONB          `json:"threat_indicators" gorm:"type:jsonb;default:'[]'"`
	MitreTactics      pq.StringArray `json:"mitre_tactics" gorm:"type:text[]"`
	MitreTechniques   pq.StringArray `json:"mitre_techniques" gorm:"type:text[]"`
	RemediationSteps  string         `json:"remediation_steps" gorm:"type:text"`
	AnalystNotes      string         `json:"analyst_notes" gorm:"type:text"`
	Metadata          JSONB          `json:"metadata" gorm:"type:jsonb;default:'{}'"`
	CreatedAt         time.Time      `json:"created_at" gorm:"index"`
	UpdatedAt         time.Time      `json:"updated_at"`

	// Relationships
	Agent        Agent          `json:"agent,omitempty" gorm:"foreignKey:AgentID"`
	Rule         *YaraRule      `json:"rule,omitempty" gorm:"foreignKey:RuleID"`
	History      []AlertHistory `json:"history,omitempty" gorm:"foreignKey:AlertID"`
	Quarantined  []QuarantinedFile `json:"quarantined_files,omitempty" gorm:"foreignKey:AlertID"`
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
	ID             uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	AgentID        uuid.UUID `json:"agent_id" gorm:"not null;index"`
	TaskType       string    `json:"task_type" gorm:"not null;size:50;check:task_type IN ('scan_file', 'update_rules', 'collect_logs', 'quarantine_file', 'kill_process', 'isolate_network');index"`
	Parameters     JSONB     `json:"parameters" gorm:"type:jsonb;default:'{}'"`
	Status         string    `json:"status" gorm:"default:'pending';size:20;check:status IN ('pending', 'sent', 'completed', 'failed', 'timeout', 'cancelled');index"`
	Priority       int       `json:"priority" gorm:"default:5;check:priority >= 1 AND priority <= 10"`
	TimeoutSeconds int       `json:"timeout_seconds" gorm:"default:300"`
	CreatedBy      string    `json:"created_by" gorm:"size:255"`
	CreatedAt      time.Time `json:"created_at" gorm:"index"`
	SentAt         *time.Time `json:"sent_at"`
	CompletedAt    *time.Time `json:"completed_at"`
	Result         JSONB     `json:"result" gorm:"type:jsonb;default:'{}'"`
	ErrorMessage   string    `json:"error_message" gorm:"type:text"`
	Progress       int       `json:"progress" gorm:"default:0;check:progress >= 0 AND progress <= 100"`

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
	ID           uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	Action       string    `json:"action" gorm:"not null;size:100;index"`
	ResourceType string    `json:"resource_type" gorm:"size:50;index"`
	ResourceID   *uuid.UUID `json:"resource_id" gorm:"index"`
	ResourceName string    `json:"resource_name" gorm:"size:255"`
	Description  string    `json:"description" gorm:"type:text"`
	UserID       string    `json:"user_id" gorm:"size:255;index"`
	IPAddress    string    `json:"ip_address" gorm:"type:inet"`
	UserAgent    string    `json:"user_agent" gorm:"type:text"`
	Success      bool      `json:"success" gorm:"default:true;index"`
	ErrorMessage string    `json:"error_message" gorm:"type:text"`
	Metadata     JSONB     `json:"metadata" gorm:"type:jsonb;default:'{}'"`
	Timestamp    time.Time `json:"timestamp" gorm:"default:now();index"`
}

// Custom table names
func (Agent) TableName() string                { return "agents" }
func (YaraRule) TableName() string             { return "yara_rules" }
func (RuleDeployment) TableName() string       { return "rule_deployments" }
func (Alert) TableName() string                { return "alerts" }
func (AlertHistory) TableName() string         { return "alert_history" }
func (Whitelist) TableName() string            { return "whitelist" }
func (QuarantinedFile) TableName() string      { return "quarantined_files" }
func (ThreatIntelligence) TableName() string   { return "threat_intelligence" }
func (AgentGroup) TableName() string           { return "agent_groups" }
func (AgentTask) TableName() string            { return "agent_tasks" }
func (SystemConfig) TableName() string         { return "system_config" }
func (NotificationSetting) TableName() string  { return "notification_settings" }
func (AuditLog) TableName() string             { return "audit_logs" }

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
	return a.Status == "online" && time.Since(a.LastSeen) < 5*time.Minute
}

func (a *Agent) IsOffline() bool {
	return a.Status == "offline" || time.Since(a.LastSeen) > time.Duration(a.HeartbeatInterval*3)*time.Second
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
	AgentID     string                 `json:"agent_id"`
	EventType   string                 `json:"event_type"`
	Timestamp   time.Time              `json:"timestamp"`
	Data        map[string]interface{} `json:"data"`
	Tags        map[string]string      `json:"tags"`
	Fields      map[string]interface{} `json:"fields"`
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