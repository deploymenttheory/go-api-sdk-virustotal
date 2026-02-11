package urls

import "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models"

// =============================================================================
// Generic Relationship Response Types (Type Aliases)
// =============================================================================

// AnalysesResponse represents the response for the analyses relationship (VT Enterprise only)
// https://docs.virustotal.com/reference/url-object-analyses
type AnalysesResponse = shared_models.RelatedObjectsResponse

// CollectionsResponse represents the response for the collections relationship
// https://docs.virustotal.com/reference/url-object-collections
type CollectionsResponse = shared_models.RelatedObjectsResponse

// CommentsResponse represents the response for the comments relationship
// https://docs.virustotal.com/reference/url-object-comments
type CommentsResponse = shared_models.RelatedObjectsResponse

// CommunicatingFilesResponse represents the response for the communicating_files relationship (VT Enterprise only)
// https://docs.virustotal.com/reference/url-object-communicating-files
type CommunicatingFilesResponse = shared_models.RelatedObjectsResponse

// ContactedDomainsResponse represents the response for the contacted_domains relationship (VT Enterprise only)
// https://docs.virustotal.com/reference/url-object-contacted-domains
type ContactedDomainsResponse = shared_models.RelatedObjectsResponse

// ContactedIPsResponse represents the response for the contacted_ips relationship (VT Enterprise only)
// https://docs.virustotal.com/reference/url-object-contacted-ips
type ContactedIPsResponse = shared_models.RelatedObjectsResponse

// DownloadedFilesResponse represents the response for the downloaded_files relationship (VT Enterprise only)
// https://docs.virustotal.com/reference/url-object-downloaded-files
type DownloadedFilesResponse = shared_models.RelatedObjectsResponse

// EmbeddedJSFilesResponse represents the response for the embedded_js_files relationship (VT Enterprise only)
// https://docs.virustotal.com/reference/url-object-embedded-js-files
type EmbeddedJSFilesResponse = shared_models.RelatedObjectsResponse

// GraphsResponse represents the response for the graphs relationship
// https://docs.virustotal.com/reference/url-object-graphs
type GraphsResponse = shared_models.RelatedObjectsResponse

// RedirectingURLsResponse represents the response for the redirecting_urls relationship (VT Enterprise only)
// https://docs.virustotal.com/reference/url-object-redirecting-urls
type RedirectingURLsResponse = shared_models.RelatedObjectsResponse

// RedirectsToResponse represents the response for the redirects_to relationship (VT Enterprise only)
// https://docs.virustotal.com/reference/url-object-redirects-to
type RedirectsToResponse = shared_models.RelatedObjectsResponse

// ReferrerFilesResponse represents the response for the referrer_files relationship (VT Enterprise only)
// https://docs.virustotal.com/reference/url-object-referrer-files
type ReferrerFilesResponse = shared_models.RelatedObjectsResponse

// ReferrerURLsResponse represents the response for the referrer_urls relationship (VT Enterprise only)
// https://docs.virustotal.com/reference/url-object-referrer-urls
type ReferrerURLsResponse = shared_models.RelatedObjectsResponse

// RelatedCommentsResponse represents the response for the related_comments relationship
// https://docs.virustotal.com/reference/url-object-related-comments
type RelatedCommentsResponse = shared_models.RelatedObjectsResponse

// RelatedReferencesResponse represents the response for the related_references relationship (VT Enterprise only)
// https://docs.virustotal.com/reference/url-object-related-references
type RelatedReferencesResponse = shared_models.RelatedObjectsResponse

// RelatedThreatActorsResponse represents the response for the related_threat_actors relationship (VT Enterprise only)
// https://docs.virustotal.com/reference/url-object-related-threat-actors
type RelatedThreatActorsResponse = shared_models.RelatedObjectsResponse

// SubmissionsResponse represents the response for the submissions relationship (VT Enterprise only)
// https://docs.virustotal.com/reference/url-object-submissions
type SubmissionsResponse = shared_models.RelatedObjectsResponse

// UserVotesResponse represents the response for the user_votes relationship
// https://docs.virustotal.com/reference/url-object-user-votes
type UserVotesResponse = shared_models.RelatedObjectsResponse

// VotesResponse represents the response for the votes relationship
// https://docs.virustotal.com/reference/url-object-votes
type VotesResponse = shared_models.RelatedObjectsResponse

// URLsRelatedByTrackerIDResponse represents the response for the urls_related_by_tracker_id relationship (VT Enterprise only)
// https://docs.virustotal.com/reference/url-object-urls-related-by-tracker-id
type URLsRelatedByTrackerIDResponse = shared_models.RelatedObjectsResponse

// =============================================================================
// Special Relationship Response Types (Single Objects)
// =============================================================================

// LastServingIPAddressResponse represents the response for the last_serving_ip_address relationship
// Returns a single IP address object
// https://docs.virustotal.com/reference/url-object-last-serving-ip-address
type LastServingIPAddressResponse struct {
	Data  shared_models.RelatedObject `json:"data"`
	Links shared_models.ObjectLinks   `json:"links"`
	Meta  shared_models.Meta          `json:"meta"`
}

// NetworkLocationResponse represents the response for the network_location relationship
// Returns a single domain or IP address object
// https://docs.virustotal.com/reference/url-object-network-location
type NetworkLocationResponse struct {
	Data  shared_models.RelatedObject `json:"data"`
	Links shared_models.ObjectLinks   `json:"links"`
	Meta  shared_models.Meta          `json:"meta"`
}

// =============================================================================
// Context Attributes for URL Relationships
// =============================================================================

// EmbeddedJSFileContextAttributes represents context attributes for embedded_js_files relationship
type EmbeddedJSFileContextAttributes struct {
	URL         string `json:"url,omitempty"`
	Timestamp   int64  `json:"timestamp,omitempty"`
	Embedded    bool   `json:"embedded,omitempty"`
	DownloadURL string `json:"download_url,omitempty"`
	Filename    string `json:"filename,omitempty"`
}

// ReferrerURLContextAttributes represents context attributes for referrer_urls relationship
type ReferrerURLContextAttributes struct {
	URL string `json:"url"`
}

// RelatedCommentsContextAttributes represents context attributes for related_comments relationship
type RelatedCommentsContextAttributes struct {
	PostedIn PostedInObject `json:"posted_in"`
}

// PostedInObject represents the object where a comment was posted
type PostedInObject struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// RelatedReferencesContextAttributes represents context attributes for related_references relationship
type RelatedReferencesContextAttributes struct {
	RelatedFrom []RelatedFromObject `json:"related_from"`
}

// RelatedThreatActorsContextAttributes represents context attributes for related_threat_actors relationship
type RelatedThreatActorsContextAttributes struct {
	RelatedFrom []RelatedFromObject `json:"related_from"`
}

// RelatedFromObject represents the source object for a relationship
type RelatedFromObject struct {
	Type       string                 `json:"type"`
	ID         string                 `json:"id"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// URLsRelatedByTrackerIDContextAttributes represents context attributes for urls_related_by_tracker_id relationship
type URLsRelatedByTrackerIDContextAttributes struct {
	URL string `json:"url"`
}
