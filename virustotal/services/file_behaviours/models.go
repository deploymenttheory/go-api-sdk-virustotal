package file_behaviours

// =============================================================================
// Common Structures
// =============================================================================

// Links represents API resource links
type Links struct {
	Self string `json:"self"`
	Next string `json:"next,omitempty"`
}

// Meta contains metadata about the response
type Meta struct {
	Count  int    `json:"count,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}

// =============================================================================
// Behaviour Summary Models
// =============================================================================

// BehaviourSummaryResponse represents the response from the behaviour summary endpoint
type BehaviourSummaryResponse struct {
	Data  BehaviourSummaryData `json:"data"`
	Links Links                `json:"links"`
}

// BehaviourSummaryData contains aggregated behaviour information from all sandboxes
type BehaviourSummaryData struct {
	CallsHighlighted           []string               `json:"calls_highlighted,omitempty"`
	FilesOpened                []string               `json:"files_opened,omitempty"`
	ModulesLoaded              []string               `json:"modules_loaded,omitempty"`
	MutexesCreated             []string               `json:"mutexes_created,omitempty"`
	MutexesOpened              []string               `json:"mutexes_opened,omitempty"`
	ProcessesTerminated        []string               `json:"processes_terminated,omitempty"`
	ProcessesTree              []ProcessTreeItem      `json:"processes_tree,omitempty"`
	RegistryKeysOpened         []string               `json:"registry_keys_opened,omitempty"`
	Tags                       []string               `json:"tags,omitempty"`
	TextHighlighted            []string               `json:"text_highlighted,omitempty"`
	ActivitiesStarted          []string               `json:"activities_started,omitempty"`
	CommandExecutions          []string               `json:"command_executions,omitempty"`
	ContentModelObservers      []string               `json:"content_model_observers,omitempty"`
	ContentModelSets           []map[string]string    `json:"content_model_sets,omitempty"`
	CryptoAlgorithmsObserved   []string               `json:"crypto_algorithms_observed,omitempty"`
	CryptoKeys                 []string               `json:"crypto_keys,omitempty"`
	CryptoPlainText            []string               `json:"crypto_plain_text,omitempty"`
	DatabasesDeleted           []string               `json:"databases_deleted,omitempty"`
	DatabasesOpened            []string               `json:"databases_opened,omitempty"`
	EncodingAlgorithmsObserved []string               `json:"encoding_algorithms_observed,omitempty"`
	FilesAttributeChanged      []string               `json:"files_attribute_changed,omitempty"`
	FilesCopied                []FileCopyItem         `json:"files_copied,omitempty"`
	FilesDeleted               []string               `json:"files_deleted,omitempty"`
	FilesDropped               []FileDroppedItem      `json:"files_dropped,omitempty"`
	FilesWritten               []string               `json:"files_written,omitempty"`
	HTTPConversations          []HTTPConversation     `json:"http_conversations,omitempty"`
	HostsFile                  string                 `json:"hosts_file,omitempty"`
	IPTraffic                  []IPTrafficItem        `json:"ip_traffic,omitempty"`
	Invokes                    []string               `json:"invokes,omitempty"`
	JA3Digests                 []string               `json:"ja3_digests,omitempty"`
	MITREAttackTechniques      []MITREAttackTechnique `json:"mitre_attack_techniques,omitempty"`
	PermissionsRequested       []string               `json:"permissions_requested,omitempty"`
	ProcessesCreated           []string               `json:"processes_created,omitempty"`
	ProcessesInjected          []string               `json:"processes_injected,omitempty"`
	ProcessesKilled            []string               `json:"processes_killed,omitempty"`
	RegistryKeysDeleted        []string               `json:"registry_keys_deleted,omitempty"`
	RegistryKeysSet            []RegistryKeySetItem   `json:"registry_keys_set,omitempty"`
	ServicesOpened             []string               `json:"services_opened,omitempty"`
	ServicesCreated            []string               `json:"services_created,omitempty"`
	ServicesStarted            []string               `json:"services_started,omitempty"`
	ServicesStopped            []string               `json:"services_stopped,omitempty"`
	ServicesDeleted            []string               `json:"services_deleted,omitempty"`
	ServicesBound              []string               `json:"services_bound,omitempty"`
	SharedPreferencesLookups   []string               `json:"shared_preferences_lookups,omitempty"`
	SharedPreferencesSets      []map[string]string    `json:"shared_preferences_sets,omitempty"`
	SigmaAnalysisResults       []SigmaAnalysisResult  `json:"sigma_analysis_results,omitempty"`
	SignatureMatches           []SignatureMatch       `json:"signature_matches,omitempty"`
	SignalsHooked              []string               `json:"signals_hooked,omitempty"`
	SignalsObserved            []string               `json:"signals_observed,omitempty"`
	SystemPropertyLookups      []string               `json:"system_property_lookups,omitempty"`
	SystemPropertySets         []map[string]string    `json:"system_property_sets,omitempty"`
	TextDecoded                []string               `json:"text_decoded,omitempty"`
	TLS                        []TLSInfo              `json:"tls,omitempty"`
	VerdictConfidence          int                    `json:"verdict_confidence,omitempty"`
	WindowsHidden              []string               `json:"windows_hidden,omitempty"`
	WindowsSearched            []string               `json:"windows_searched,omitempty"`
	IDSAlerts                  []IDSAlert             `json:"ids_alerts,omitempty"`
	DNSLookups                 []DNSLookup            `json:"dns_lookups,omitempty"`
}

// ProcessTreeItem represents a process in the process tree
type ProcessTreeItem struct {
	ProcessID string            `json:"process_id"`
	Name      string            `json:"name"`
	Children  []ProcessTreeItem `json:"children,omitempty"`
}

// FileCopyItem represents a file copy operation
type FileCopyItem struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

// FileDroppedItem represents a dropped file
type FileDroppedItem struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Type   string `json:"type,omitempty"`
}

// HTTPConversation represents an HTTP conversation
type HTTPConversation struct {
	URL                string            `json:"url"`
	RequestMethod      string            `json:"request_method"`
	RequestHeaders     map[string]string `json:"request_headers,omitempty"`
	ResponseHeaders    map[string]string `json:"response_headers,omitempty"`
	ResponseStatusCode int               `json:"response_status_code,omitempty"`
}

// IPTrafficItem represents IP traffic
type IPTrafficItem struct {
	TransportLayerProtocol string `json:"transport_layer_protocol"`
	DestinationIP          string `json:"destination_ip"`
	DestinationPort        int    `json:"destination_port"`
}

// MITREAttackTechnique represents a MITRE ATT&CK technique
type MITREAttackTechnique struct {
	SignatureDescription string         `json:"signature_description"`
	ID                   string         `json:"id"`
	Severity             string         `json:"severity"`
	Refs                 []SignatureRef `json:"refs,omitempty"`
}

// SignatureRef represents a reference to a signature match
type SignatureRef struct {
	Ref   string `json:"ref"`
	Value string `json:"value"`
}

// RegistryKeySetItem represents a registry key set operation
type RegistryKeySetItem struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// SigmaAnalysisResult represents a sigma analysis result
type SigmaAnalysisResult struct {
	RuleTitle       string              `json:"rule_title"`
	RuleSource      string              `json:"rule_source"`
	MatchContext    []SigmaMatchContext `json:"match_context,omitempty"`
	RuleLevel       string              `json:"rule_level"`
	RuleDescription string              `json:"rule_description,omitempty"`
	RuleAuthor      string              `json:"rule_author,omitempty"`
	RuleID          string              `json:"rule_id"`
}

// SigmaMatchContext represents matched events in sigma analysis
type SigmaMatchContext struct {
	Values map[string]string `json:"values"`
}

// SignatureMatch represents a signature match
type SignatureMatch struct {
	Format      string         `json:"format,omitempty"`
	Authors     []string       `json:"authors,omitempty"`
	RuleSrc     string         `json:"rule_src,omitempty"`
	Name        string         `json:"name,omitempty"`
	Description string         `json:"description,omitempty"`
	ID          string         `json:"id,omitempty"`
	MatchData   []string       `json:"match_data,omitempty"`
	Severity    string         `json:"severity,omitempty"`
	Refs        []SignatureRef `json:"refs,omitempty"`
}

// TLSInfo represents TLS connection information
type TLSInfo struct {
	Issuer       map[string]string `json:"issuer,omitempty"`
	JA3          string            `json:"ja3,omitempty"`
	JA3S         string            `json:"ja3s,omitempty"`
	SerialNumber string            `json:"serial_number,omitempty"`
	SNI          string            `json:"sni,omitempty"`
	Subject      map[string]string `json:"subject,omitempty"`
	Thumbprint   string            `json:"thumbprint,omitempty"`
	Version      string            `json:"version,omitempty"`
}

// IDSAlert represents an IDS alert
type IDSAlert struct {
	AlertContext  IDSAlertContext `json:"alert_context"`
	AlertSeverity string          `json:"alert_severity"`
	RuleID        string          `json:"rule_id"`
	RuleMsg       string          `json:"rule_msg"`
	RuleSource    string          `json:"rule_source,omitempty"`
	RuleCategory  string          `json:"rule_category,omitempty"`
}

// IDSAlertContext represents the context of an IDS alert
type IDSAlertContext struct {
	DestIP   string `json:"dest_ip,omitempty"`
	DestPort int    `json:"dest_port,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	SrcIP    string `json:"src_ip,omitempty"`
	SrcPort  int    `json:"src_port,omitempty"`
	URL      string `json:"url,omitempty"`
}

// DNSLookup represents a DNS lookup
type DNSLookup struct {
	Hostname    string   `json:"hostname"`
	ResolvedIPs []string `json:"resolved_ips,omitempty"`
}

// =============================================================================
// MITRE ATT&CK Trees Models
// =============================================================================

// MitreTreesResponse represents the response from the MITRE trees endpoint
type MitreTreesResponse struct {
	Data  map[string]SandboxTactics `json:"data"`
	Links Links                     `json:"links"`
}

// SandboxTactics represents tactics observed in a sandbox
type SandboxTactics struct {
	Tactics []Tactic `json:"tactics"`
}

// Tactic represents a MITRE ATT&CK tactic
type Tactic struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Link        string      `json:"link"`
	Techniques  []Technique `json:"techniques"`
}

// Technique represents a MITRE ATT&CK technique
type Technique struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Link        string      `json:"link"`
	Signatures  []Signature `json:"signatures"`
}

// Signature represents a signature within a technique
type Signature struct {
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// =============================================================================
// All Behaviours Models
// =============================================================================

// AllBehavioursResponse represents the response from the all behaviours endpoint
type AllBehavioursResponse struct {
	Meta  Meta              `json:"meta"`
	Data  []BehaviourReport `json:"data"`
	Links Links             `json:"links"`
}

// BehaviourReport represents a single behaviour report from a sandbox
type BehaviourReport struct {
	Type       string              `json:"type"`
	ID         string              `json:"id"`
	Links      Links               `json:"links"`
	Attributes BehaviourAttributes `json:"attributes"`
}

// BehaviourAttributes contains the detailed behaviour attributes
type BehaviourAttributes struct {
	AnalysisDate               int64                  `json:"analysis_date"`
	Behash                     string                 `json:"behash"`
	SandboxName                string                 `json:"sandbox_name"`
	HasHTMLReport              bool                   `json:"has_html_report"`
	HasPCAP                    bool                   `json:"has_pcap"`
	HasEVTX                    bool                   `json:"has_evtx"`
	HasMemdump                 bool                   `json:"has_memdump"`
	LastModificationDate       int64                  `json:"last_modification_date"`
	CallsHighlighted           []string               `json:"calls_highlighted,omitempty"`
	CommandExecutions          []string               `json:"command_executions,omitempty"`
	FilesOpened                []string               `json:"files_opened,omitempty"`
	FilesWritten               []string               `json:"files_written,omitempty"`
	FilesDeleted               []string               `json:"files_deleted,omitempty"`
	FilesAttributeChanged      []string               `json:"files_attribute_changed,omitempty"`
	FilesCopied                []FileCopyItem         `json:"files_copied,omitempty"`
	FilesDropped               []FileDroppedItem      `json:"files_dropped,omitempty"`
	HostsFile                  string                 `json:"hosts_file,omitempty"`
	IDSAlerts                  []IDSAlert             `json:"ids_alerts,omitempty"`
	ProcessesTerminated        []string               `json:"processes_terminated,omitempty"`
	ProcessesKilled            []string               `json:"processes_killed,omitempty"`
	ProcessesInjected          []string               `json:"processes_injected,omitempty"`
	ProcessesCreated           []string               `json:"processes_created,omitempty"`
	ServicesOpened             []string               `json:"services_opened,omitempty"`
	ServicesCreated            []string               `json:"services_created,omitempty"`
	ServicesStarted            []string               `json:"services_started,omitempty"`
	ServicesStopped            []string               `json:"services_stopped,omitempty"`
	ServicesDeleted            []string               `json:"services_deleted,omitempty"`
	ServicesBound              []string               `json:"services_bound,omitempty"`
	WindowsSearched            []string               `json:"windows_searched,omitempty"`
	WindowsHidden              []string               `json:"windows_hidden,omitempty"`
	MutexesOpened              []string               `json:"mutexes_opened,omitempty"`
	MutexesCreated             []string               `json:"mutexes_created,omitempty"`
	SignalsObserved            []string               `json:"signals_observed,omitempty"`
	Invokes                    []string               `json:"invokes,omitempty"`
	CryptoAlgorithmsObserved   []string               `json:"crypto_algorithms_observed,omitempty"`
	CryptoKeys                 []string               `json:"crypto_keys,omitempty"`
	CryptoPlainText            []string               `json:"crypto_plain_text,omitempty"`
	TextDecoded                []string               `json:"text_decoded,omitempty"`
	TextHighlighted            []string               `json:"text_highlighted,omitempty"`
	VerdictConfidence          int                    `json:"verdict_confidence,omitempty"`
	JA3Digests                 []string               `json:"ja3_digests,omitempty"`
	TLS                        []TLSInfo              `json:"tls,omitempty"`
	SigmaAnalysisResults       []SigmaAnalysisResult  `json:"sigma_analysis_results,omitempty"`
	SignatureMatches           []SignatureMatch       `json:"signature_matches,omitempty"`
	MITREAttackTechniques      []MITREAttackTechnique `json:"mitre_attack_techniques,omitempty"`
	Tags                       []string               `json:"tags,omitempty"`
	Verdicts                   []string               `json:"verdicts,omitempty"`
	ModulesLoaded              []string               `json:"modules_loaded,omitempty"`
	RegistryKeysOpened         []string               `json:"registry_keys_opened,omitempty"`
	RegistryKeysSet            []RegistryKeySetItem   `json:"registry_keys_set,omitempty"`
	RegistryKeysDeleted        []string               `json:"registry_keys_deleted,omitempty"`
	IPTraffic                  []IPTrafficItem        `json:"ip_traffic,omitempty"`
	ProcessesTree              []ProcessTreeItem      `json:"processes_tree,omitempty"`
	MemoryDumps                []MemoryDumpItem       `json:"memory_dumps,omitempty"`
	DNSLookups                 []DNSLookup            `json:"dns_lookups,omitempty"`
	HTTPConversations          []HTTPConversation     `json:"http_conversations,omitempty"`
	ActivitiesStarted          []string               `json:"activities_started,omitempty"`
	ContentModelObservers      []string               `json:"content_model_observers,omitempty"`
	ContentModelSets           []map[string]string    `json:"content_model_sets,omitempty"`
	DatabasesDeleted           []string               `json:"databases_deleted,omitempty"`
	DatabasesOpened            []string               `json:"databases_opened,omitempty"`
	PermissionsRequested       []string               `json:"permissions_requested,omitempty"`
	SharedPreferencesLookups   []string               `json:"shared_preferences_lookups,omitempty"`
	SharedPreferencesSets      []map[string]string    `json:"shared_preferences_sets,omitempty"`
	SignalsHooked              []string               `json:"signals_hooked,omitempty"`
	SystemPropertyLookups      []string               `json:"system_property_lookups,omitempty"`
	SystemPropertySets         []map[string]string    `json:"system_property_sets,omitempty"`
	EncodingAlgorithmsObserved []string               `json:"encoding_algorithms_observed,omitempty"`
}

// MemoryDumpItem represents a memory dump file
type MemoryDumpItem struct {
	Process     string         `json:"process"`
	FileName    string         `json:"file_name"`
	Refs        []SignatureRef `json:"refs,omitempty"`
	Stage       string         `json:"stage,omitempty"`
	BaseAddress string         `json:"base_address,omitempty"`
	Size        string         `json:"size,omitempty"`
}

// =============================================================================
// Single Behaviour Report Models
// =============================================================================

// BehaviourReportResponse represents the response for a single behaviour report
type BehaviourReportResponse struct {
	Data BehaviourReport `json:"data"`
}

// =============================================================================
// Related Objects Models
// =============================================================================

// RelatedObjectsResponse represents objects related to a behaviour report
type RelatedObjectsResponse struct {
	Data  []RelatedObject `json:"data"`
	Links Links           `json:"links,omitempty"`
	Meta  Meta            `json:"meta,omitempty"`
}

// RelatedObject represents a related object
type RelatedObject struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Links      Links          `json:"links,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// =============================================================================
// Object Descriptors Models
// =============================================================================

// ObjectDescriptorsResponse represents object descriptors
type ObjectDescriptorsResponse struct {
	Data  []ObjectDescriptor `json:"data"`
	Links Links              `json:"links,omitempty"`
	Meta  Meta               `json:"meta,omitempty"`
}

// ObjectDescriptor represents an object descriptor
type ObjectDescriptor struct {
	Type             string         `json:"type"`
	ID               string         `json:"id"`
	Links            Links          `json:"links,omitempty"`
	ContextAttributes map[string]any `json:"context_attributes,omitempty"`
}

// =============================================================================
// Request Query Options
// =============================================================================

// GetRelatedObjectsOptions contains optional query parameters for requests
type GetRelatedObjectsOptions struct {
	Limit  int    // Maximum number of results to return
	Cursor string // Cursor for pagination
}
