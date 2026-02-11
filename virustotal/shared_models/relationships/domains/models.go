package domains

import "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models"

// =============================================================================
// Generic Relationship Response Types (Type Aliases)
// =============================================================================

// CollectionsResponse represents the response from getting collections containing the domain
type CollectionsResponse = shared_models.RelatedObjectsResponse

// CommentsResponse represents the response from getting comments on the domain
type CommentsResponse = shared_models.RelatedObjectsResponse

// CommunicatingFilesResponse represents the response from getting files that communicate with the domain
type CommunicatingFilesResponse = shared_models.RelatedObjectsResponse

// DownloadedFilesResponse represents the response from getting files downloaded from the domain (VT Enterprise only)
type DownloadedFilesResponse = shared_models.RelatedObjectsResponse

// GraphsResponse represents the response from getting graphs containing the domain
type GraphsResponse = shared_models.RelatedObjectsResponse

// HistoricalWhoisResponse represents the response from getting historical WHOIS information
type HistoricalWhoisResponse = shared_models.RelatedObjectsResponse

// ReferrerFilesResponse represents the response from getting files containing the domain
type ReferrerFilesResponse = shared_models.RelatedObjectsResponse

// SiblingsResponse represents the response from getting sibling domains
type SiblingsResponse = shared_models.RelatedObjectsResponse

// SubdomainsResponse represents the response from getting subdomains
type SubdomainsResponse = shared_models.RelatedObjectsResponse

// URLsResponse represents the response from getting URLs under the domain (VT Enterprise only)
type URLsResponse = shared_models.RelatedObjectsResponse

// UserVotesResponse represents the response from getting current user's votes
type UserVotesResponse = shared_models.RelatedObjectsResponse

// VotesResponse represents the response from getting all votes on the domain
type VotesResponse = shared_models.RelatedObjectsResponse

// ResolutionsResponse represents the response from getting DNS resolutions
type ResolutionsResponse = shared_models.RelatedObjectsResponse

// =============================================================================
// DNS Record Relationships (VT Enterprise Only)
// =============================================================================

// CAARecordsResponse represents the response from getting CAA records
type CAARecordsResponse = shared_models.RelatedObjectsResponse

// CNAMERecordsResponse represents the response from getting CNAME records
type CNAMERecordsResponse = shared_models.RelatedObjectsResponse

// MXRecordsResponse represents the response from getting MX records
type MXRecordsResponse = shared_models.RelatedObjectsResponse

// NSRecordsResponse represents the response from getting NS records
type NSRecordsResponse = shared_models.RelatedObjectsResponse

// SOARecordsResponse represents the response from getting SOA records
type SOARecordsResponse = shared_models.RelatedObjectsResponse

// =============================================================================
// SSL Certificate Relationship
// =============================================================================

// HistoricalSSLCertificatesResponse represents the response from getting historical SSL certificates
type HistoricalSSLCertificatesResponse = shared_models.RelatedObjectsResponse

// =============================================================================
// Parent Relationships (Single Object Responses)
// =============================================================================

// ImmediateParentResponse represents the response from getting the immediate parent domain
type ImmediateParentResponse struct {
	Data  shared_models.RelatedObject `json:"data"`
	Links shared_models.Links         `json:"links,omitempty"`
	Meta  *shared_models.Meta         `json:"meta,omitempty"`
}

// ParentResponse represents the response from getting the top parent domain
type ParentResponse struct {
	Data  shared_models.RelatedObject `json:"data"`
	Links shared_models.Links         `json:"links,omitempty"`
	Meta  *shared_models.Meta         `json:"meta,omitempty"`
}

// =============================================================================
// Related Comments/References/ThreatActors Relationships
// =============================================================================

// RelatedCommentsResponse represents the response from getting comments in related objects
type RelatedCommentsResponse = shared_models.RelatedObjectsResponse

// RelatedReferencesResponse represents the response from getting related references (VT Enterprise only)
type RelatedReferencesResponse = shared_models.RelatedObjectsResponse

// RelatedThreatActorsResponse represents the response from getting related threat actors (VT Enterprise only)
type RelatedThreatActorsResponse = shared_models.RelatedObjectsResponse

// =============================================================================
// Context Attributes for DNS Records
// =============================================================================

// CAARecordContextAttributes contains context attributes for CAA records
type CAARecordContextAttributes struct {
	Timestamp int64  `json:"timestamp"` // Date when the relationship was created (UTC timestamp)
	Flag      int    `json:"flag"`      // An unsigned integer between 0-255
	Tag       string `json:"tag"`       // Property identifier represented by the record
	TTL       int    `json:"ttl"`       // Time to live
}

// CNAMERecordContextAttributes contains context attributes for CNAME records
type CNAMERecordContextAttributes struct {
	Timestamp int64 `json:"timestamp"` // Date when the relationship was created (UTC timestamp)
	TTL       int   `json:"ttl"`       // Time to live
}

// MXRecordContextAttributes contains context attributes for MX records
type MXRecordContextAttributes struct {
	Timestamp int64 `json:"timestamp"` // Date when the relationship was created (UTC timestamp)
	Priority  int   `json:"priority"`  // Mail server priority
	TTL       int   `json:"ttl"`       // Time to live
}

// NSRecordContextAttributes contains context attributes for NS records
type NSRecordContextAttributes struct {
	Timestamp int64 `json:"timestamp"` // Date when the relationship was created (UTC timestamp)
	TTL       int   `json:"ttl"`       // Time to live
}

// SOARecordContextAttributes contains context attributes for SOA records
type SOARecordContextAttributes struct {
	RName     string `json:"rname"`     // Responsible party email
	Retry     int    `json:"retry"`     // Retry interval
	Timestamp int64  `json:"timestamp"` // Date when the relationship was created (UTC timestamp)
	Refresh   int    `json:"refresh"`   // Refresh interval
	Minimum   int    `json:"minimum"`   // Minimum TTL
	Expire    int    `json:"expire"`    // Expiration time
	TTL       int    `json:"ttl"`       // Time to live
	Serial    int    `json:"serial"`    // Serial number
}

// =============================================================================
// Context Attributes for SSL Certificates
// =============================================================================

// HistoricalSSLCertificatesContextAttributes contains context attributes for historical SSL certificates
type HistoricalSSLCertificatesContextAttributes struct {
	FirstSeenDate string `json:"first_seen_date"` // Date the certificate was first retrieved (YYYY-MM-DD format)
	Port          string `json:"port"`            // Port where the domain was serving requests (typically "443")
}

// =============================================================================
// Context Attributes for Related Comments
// =============================================================================

// RelatedCommentsContextAttributes contains context attributes for related comments
type RelatedCommentsContextAttributes struct {
	PostedIn PostedInObject `json:"posted_in"` // Object where the comment was posted
}

// PostedInObject specifies the object where a comment was posted
type PostedInObject struct {
	ID   string `json:"id"`   // Object ID
	Type string `json:"type"` // Object type
}

// =============================================================================
// Context Attributes for Related References and Threat Actors
// =============================================================================

// RelatedReferencesContextAttributes contains context attributes for related references
type RelatedReferencesContextAttributes struct {
	RelatedFrom []RelatedFromObject `json:"related_from"` // Objects from which the reference is related
}

// RelatedThreatActorsContextAttributes contains context attributes for related threat actors
type RelatedThreatActorsContextAttributes struct {
	RelatedFrom []RelatedFromObject `json:"related_from"` // Objects from which the threat actor is related
}

// RelatedFromObject specifies an object from which something is related
type RelatedFromObject struct {
	Type       string                 `json:"type"`                 // Object type
	ID         string                 `json:"id"`                   // Object ID
	Attributes map[string]interface{} `json:"attributes,omitempty"` // Optional object attributes (e.g., name)
}
