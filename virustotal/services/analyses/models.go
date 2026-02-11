package analyses

import (
	analyses_relationships "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models/relationships/analyses"
)

// =============================================================================
// Analysis Models
// =============================================================================

// Analysis represents an analysis object from VirusTotal API
// Matches the schema from API v3 documentation
type Analysis struct {
	Type       string             `json:"type"`       // Object type (always "analysis")
	ID         string             `json:"id"`         // Analysis ID
	Links      *Links             `json:"links,omitempty"`
	Attributes AnalysisAttributes `json:"attributes"`
}

// Links represents the links section of an object
type Links struct {
	Self string `json:"self"` // URL to this object
}

// AnalysisAttributes contains the attributes of an analysis
type AnalysisAttributes struct {
	Date    int64                      `json:"date"`              // Unix timestamp when the analysis was performed
	Results map[string]EngineResult    `json:"results,omitempty"` // Results from each security engine
	Stats   AnalysisStats              `json:"stats"`             // Summary statistics of results
	Status  string                     `json:"status"`            // "completed", "queued", or "in-progress"
}

// EngineResult represents the result from a single security engine
type EngineResult struct {
	Category      string `json:"category"`                // "confirmed-timeout", "timeout", "failure", "harmless", "undetected", "suspicious", "malicious", "type-unsupported"
	EngineName    string `json:"engine_name"`             // Name of the security engine
	EngineUpdate  string `json:"engine_update,omitempty"` // Engine definition date (%Y%M%D format) - file analyses only
	EngineVersion string `json:"engine_version,omitempty"` // Engine version string - file analyses only
	Method        string `json:"method,omitempty"`        // Detection method
	Result        string `json:"result,omitempty"`        // Specific engine verdict (may be null)
}

// AnalysisStats contains summary statistics of analysis results
type AnalysisStats struct {
	ConfirmedTimeout int `json:"confirmed-timeout,omitempty"`
	Failure          int `json:"failure,omitempty"`
	Harmless         int `json:"harmless,omitempty"`
	Malicious        int `json:"malicious,omitempty"`
	Suspicious       int `json:"suspicious,omitempty"`
	Timeout          int `json:"timeout,omitempty"`
	TypeUnsupported  int `json:"type-unsupported,omitempty"`
	Undetected       int `json:"undetected,omitempty"`
}

// AnalysisResponse is the response wrapper for analysis requests
type AnalysisResponse struct {
	Data Analysis `json:"data"`
}

// =============================================================================
// Submission Models
// =============================================================================

// Submission represents a submission object from VirusTotal API
type Submission struct {
	Type       string               `json:"type"`       // Object type (always "submission")
	ID         string               `json:"id"`         // Submission ID
	Links      *Links               `json:"links,omitempty"`
	Attributes SubmissionAttributes `json:"attributes"`
}

// SubmissionAttributes contains the attributes of a submission
type SubmissionAttributes struct {
	Date      int64  `json:"date"`                // Unix timestamp of submission
	Interface string `json:"interface,omitempty"` // How item entered system (api, UI, email, etc.) - Premium API only
	Country   string `json:"country,omitempty"`   // ISO country code of submission origin - Premium API only
	City      string `json:"city,omitempty"`      // City of submission origin - Premium API only
	Name      string `json:"name,omitempty"`      // Filename submitted with - Premium API only
	SourceKey string `json:"source_key,omitempty"` // Anonymized submitter token - Premium API only
}

// SubmissionResponse is the response wrapper for submission requests
type SubmissionResponse struct {
	Data Submission `json:"data"`
}

// =============================================================================
// Operation Models
// =============================================================================

// Operation represents an operation object from VirusTotal API
// Operations represent asynchronous API operations that cannot complete immediately
type Operation struct {
	Type       string              `json:"type"`       // Object type (always "operation")
	ID         string              `json:"id"`         // Operation ID
	Links      *Links              `json:"links,omitempty"`
	Attributes OperationAttributes `json:"attributes"`
}

// OperationAttributes contains the attributes of an operation
type OperationAttributes struct {
	Status string `json:"status"` // "aborted", "finished", or "running"
}

// OperationResponse is the response wrapper for operation requests
type OperationResponse struct {
	Data Operation `json:"data"`
}

// =============================================================================
// Related Objects Models
// =============================================================================

// RelatedObjectsResponse represents the response for related objects
type RelatedObjectsResponse struct {
	Data  []RelatedObject `json:"data"`
	Links RelatedLinks    `json:"links,omitempty"`
	Meta  Meta            `json:"meta,omitempty"`
}

// RelatedObject represents an object related to an analysis
type RelatedObject struct {
	Type              string         `json:"type"`                         // Object type (e.g., "file", "url")
	ID                string         `json:"id"`                           // Object ID
	Links             *Links         `json:"links,omitempty"`              // Object links
	Attributes        map[string]any `json:"attributes,omitempty"`         // Object attributes (varies by type)
	ContextAttributes map[string]any `json:"context_attributes,omitempty"` // Context-specific attributes
}

// RelatedLinks represents pagination links
type RelatedLinks struct {
	Self string `json:"self,omitempty"`
	Next string `json:"next,omitempty"` // Next page URL
}

// Meta represents metadata about the response
type Meta struct {
	Count  int    `json:"count,omitempty"`
	Cursor string `json:"cursor,omitempty"` // Pagination cursor
}

// GetRelatedObjectsOptions contains optional parameters for related objects requests
type GetRelatedObjectsOptions struct {
	Limit  int    // Number of items per page (default 10, max 40)
	Cursor string // Continuation cursor for pagination
}

// =============================================================================
// Object Descriptors Models
// =============================================================================

// RelatedObjectDescriptorsResponse represents the response for related object descriptors
type RelatedObjectDescriptorsResponse struct {
	Data  []ObjectDescriptor `json:"data"`
	Links RelatedLinks       `json:"links,omitempty"`
	Meta  Meta               `json:"meta,omitempty"`
}

// ObjectDescriptor represents a lightweight descriptor for a related object
type ObjectDescriptor struct {
	Type              string         `json:"type"`                         // Object type
	ID                string         `json:"id"`                           // Object ID
	ContextAttributes map[string]any `json:"context_attributes,omitempty"` // Context-specific attributes
}

// =============================================================================
// Relationship Response Types
// =============================================================================

// ItemResponse represents the response for the item relationship
type ItemResponse = analyses_relationships.ItemResponse
