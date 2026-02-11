package ip_addresses

import "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models"

// =============================================================================
// Collections Relationship
// =============================================================================

// CollectionsResponse represents collections containing this IP address
type CollectionsResponse = shared_models.RelatedObjectsResponse

// =============================================================================
// Comments Relationship
// =============================================================================

// CommentsResponse represents comments posted on the IP address
type CommentsResponse = shared_models.RelatedObjectsResponse

// =============================================================================
// Communicating Files Relationship
// =============================================================================

// CommunicatingFilesResponse represents files that communicate with the IP address
type CommunicatingFilesResponse = shared_models.RelatedObjectsResponse

// =============================================================================
// Downloaded Files Relationship (VT Enterprise only)
// =============================================================================

// DownloadedFilesResponse represents files downloaded from the IP address
type DownloadedFilesResponse = shared_models.RelatedObjectsResponse

// =============================================================================
// Graphs Relationship
// =============================================================================

// GraphsResponse represents graphs including the IP address
type GraphsResponse = shared_models.RelatedObjectsResponse

// =============================================================================
// Historical SSL Certificates Relationship
// =============================================================================

// HistoricalSSLCertificatesContextAttributes represents context attributes for SSL certificates
type HistoricalSSLCertificatesContextAttributes struct {
	FirstSeenDate string `json:"first_seen_date"` // Date the certificate was first retrieved (YYYY-MM-DD format)
	Port          int    `json:"port"`            // Port where the certificate was served (typically 443)
}

// HistoricalSSLCertificatesResponse represents SSL certificates associated with the IP
type HistoricalSSLCertificatesResponse = shared_models.RelatedObjectsResponse

// =============================================================================
// Historical WHOIS Relationship
// =============================================================================

// HistoricalWhoisResponse represents WHOIS information for the IP address
type HistoricalWhoisResponse = shared_models.RelatedObjectsResponse

// =============================================================================
// Related Comments Relationship
// =============================================================================

// RelatedCommentsContextAttributes represents context attributes for related comments
type RelatedCommentsContextAttributes struct {
	PostedIn *PostedInObject `json:"posted_in,omitempty"` // Specifies the object where the comment was posted
}

// PostedInObject represents the object where a comment was posted
type PostedInObject struct {
	ID   string `json:"id"`   // Object ID
	Type string `json:"type"` // Object type
}

// RelatedCommentsResponse represents community posted comments in the IP's related objects
type RelatedCommentsResponse = shared_models.RelatedObjectsResponse

// =============================================================================
// Related References Relationship (VT Enterprise only)
// =============================================================================

// RelatedReferencesContextAttributes represents context attributes for related references
type RelatedReferencesContextAttributes struct {
	RelatedFrom []RelatedFromObject `json:"related_from"` // Objects this reference is related from
}

// RelatedFromObject represents an object that a reference is related from
type RelatedFromObject struct {
	Type       string         `json:"type"`                 // Object type
	ID         string         `json:"id"`                   // Object ID
	Attributes map[string]any `json:"attributes,omitempty"` // Object attributes
}

// RelatedReferencesResponse represents references related to the IP address
type RelatedReferencesResponse = shared_models.RelatedObjectsResponse

// =============================================================================
// Related Threat Actors Relationship (VT Enterprise only)
// =============================================================================

// RelatedThreatActorsContextAttributes represents context attributes for related threat actors
type RelatedThreatActorsContextAttributes struct {
	RelatedFrom []RelatedFromObject `json:"related_from"` // Objects this threat actor is related from
}

// RelatedThreatActorsResponse represents threat actors related to the IP address
type RelatedThreatActorsResponse = shared_models.RelatedObjectsResponse

// =============================================================================
// Referrer Files Relationship
// =============================================================================

// ReferrerFilesResponse represents files containing the IP address
type ReferrerFilesResponse = shared_models.RelatedObjectsResponse

// =============================================================================
// Resolutions Relationship
// =============================================================================

// ResolutionsResponse represents IP address' resolutions
type ResolutionsResponse = shared_models.RelatedObjectsResponse

// =============================================================================
// URLs Relationship (VT Enterprise only)
// =============================================================================

// URLsResponse represents URLs related to the IP address
type URLsResponse = shared_models.RelatedObjectsResponse

// =============================================================================
// User Votes Relationship
// =============================================================================

// UserVotesResponse represents votes for the current user
type UserVotesResponse = shared_models.RelatedObjectsResponse

// =============================================================================
// Votes Relationship
// =============================================================================

// VotesResponse represents all votes on the IP address
type VotesResponse = shared_models.RelatedObjectsResponse
