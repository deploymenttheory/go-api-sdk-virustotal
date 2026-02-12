package urls

import (
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models"
	url_relationships "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models/relationships/urls"
)

// =============================================================================
// Common Structures
// =============================================================================

type Links = shared_models.ObjectLinks
type RelatedLinks = shared_models.Links
type Meta = shared_models.Meta

type Votes struct {
	Harmless  int `json:"harmless,omitempty"`
	Malicious int `json:"malicious,omitempty"`
}

// =============================================================================
// URL Scan Models
// =============================================================================

type ScanURLRequest struct {
	URL string `json:"url"`
}

type ScanURLResponse struct {
	Data ScanURLData `json:"data"`
}

type ScanURLData struct {
	Type string        `json:"type"`
	ID   string        `json:"id"`
	Links Links        `json:"links"`
}

// =============================================================================
// URL Report Models
// =============================================================================

type URLResponse struct {
	Data URL `json:"data"`
}

type URL struct {
	Type       string        `json:"type"`
	ID         string        `json:"id"`
	Links      Links         `json:"links"`
	Attributes URLAttributes `json:"attributes"`
}

type URLAttributes struct {
	URL                   string                  `json:"url,omitempty"`
	FirstSubmissionDate   int64                   `json:"first_submission_date,omitempty"`
	LastAnalysisDate      int64                   `json:"last_analysis_date,omitempty"`
	LastAnalysisResults   map[string]EngineResult `json:"last_analysis_results,omitempty"`
	LastAnalysisStats     LastAnalysisStats       `json:"last_analysis_stats,omitempty"`
	LastFinalURL          string                  `json:"last_final_url,omitempty"`
	LastHTTPResponseCode  int                     `json:"last_http_response_code,omitempty"`
	LastHTTPResponseContentLength int             `json:"last_http_response_content_length,omitempty"`
	LastHTTPResponseContentSHA256 string          `json:"last_http_response_content_sha256,omitempty"`
	LastHTTPResponseCookies       map[string]string `json:"last_http_response_cookies,omitempty"`
	LastHTTPResponseHeaders       map[string]string `json:"last_http_response_headers,omitempty"`
	LastModificationDate  int64                   `json:"last_modification_date,omitempty"`
	LastSubmissionDate    int64                   `json:"last_submission_date,omitempty"`
	Reputation            int                     `json:"reputation,omitempty"`
	Tags                  []string                `json:"tags,omitempty"`
	TimesSubmitted        int                     `json:"times_submitted,omitempty"`
	Title                 string                  `json:"title,omitempty"`
	TotalVotes            Votes                   `json:"total_votes,omitempty"`
	Categories            map[string]string       `json:"categories,omitempty"`
	HTMLMeta              map[string]string       `json:"html_meta,omitempty"`
	OutgoingLinks         []string                `json:"outgoing_links,omitempty"`
	RedirectionChain      []string                `json:"redirection_chain,omitempty"`
	TargetedBrand         string                  `json:"targeted_brand,omitempty"`
	ThreatNames           []string                `json:"threat_names,omitempty"`
	TrackerID             string                  `json:"tracker_id,omitempty"`
}

type EngineResult struct {
	Category   string `json:"category"`
	EngineName string `json:"engine_name"`
	Method     string `json:"method"`
	Result     string `json:"result"`
}

type LastAnalysisStats struct {
	Harmless   int `json:"harmless,omitempty"`
	Malicious  int `json:"malicious,omitempty"`
	Suspicious int `json:"suspicious,omitempty"`
	Undetected int `json:"undetected,omitempty"`
	Timeout    int `json:"timeout,omitempty"`
}

// =============================================================================
// URL Rescan Models
// =============================================================================

type RescanURLResponse struct {
	Data RescanURLData `json:"data"`
}

type RescanURLData struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// =============================================================================
// Comment Models
// =============================================================================

type AddCommentRequest struct {
	Data CommentData `json:"data"`
}

type CommentData struct {
	Type       string            `json:"type"`
	Attributes CommentAttributes `json:"attributes"`
}

type CommentAttributes struct {
	Text string `json:"text"`
}

type AddCommentResponse struct {
	Data Comment `json:"data"`
}

type Comment struct {
	Type       string                    `json:"type"`
	ID         string                    `json:"id"`
	Links      Links                     `json:"links"`
	Attributes CommentAttributesResponse `json:"attributes"`
}

type CommentAttributesResponse struct {
	Date  int64    `json:"date"`
	Text  string   `json:"text"`
	HTML  string   `json:"html,omitempty"`
	Tags  []string `json:"tags,omitempty"`
	Votes Votes    `json:"votes,omitempty"`
}

// =============================================================================
// Related Objects Models
// =============================================================================

type RelatedObjectsResponse struct {
	Data  []RelatedObject `json:"data"`
	Links RelatedLinks    `json:"links,omitempty"`
	Meta  Meta            `json:"meta,omitempty"`
}

type RelatedObject struct {
	Type              string         `json:"type"`
	ID                string         `json:"id"`
	Links             Links          `json:"links,omitempty"`
	Attributes        map[string]any `json:"attributes,omitempty"`
	ContextAttributes map[string]any `json:"context_attributes,omitempty"`
}

type GetRelatedObjectsOptions struct {
	Limit  int
	Cursor string
}

// =============================================================================
// Object Descriptors Models
// =============================================================================

type ObjectDescriptorsResponse struct {
	Data  []ObjectDescriptor `json:"data"`
	Links RelatedLinks       `json:"links,omitempty"`
	Meta  Meta               `json:"meta,omitempty"`
}

type ObjectDescriptor struct {
	Type              string         `json:"type"`
	ID                string         `json:"id"`
	ContextAttributes map[string]any `json:"context_attributes,omitempty"`
}

// =============================================================================
// Votes Models
// =============================================================================

type VotesResponse struct {
	Data  []Vote       `json:"data"`
	Links RelatedLinks `json:"links,omitempty"`
	Meta  Meta         `json:"meta,omitempty"`
}

type Vote struct {
	Attributes VoteAttributes `json:"attributes"`
	ID         string         `json:"id"`
	Links      Links          `json:"links"`
	Type       string         `json:"type"`
}

type VoteAttributes struct {
	Date    int64  `json:"date"`
	Value   int    `json:"value"`
	Verdict string `json:"verdict"`
}

type GetVotesOptions struct {
	Limit  int
	Cursor string
}

// =============================================================================
// Add Vote Models
// =============================================================================

type AddVoteRequest struct {
	Data VoteData `json:"data"`
}

type VoteData struct {
	Type       string             `json:"type"`
	Attributes VoteDataAttributes `json:"attributes"`
}

type VoteDataAttributes struct {
	Verdict string `json:"verdict"`
}

type AddVoteResponse struct {
	Data Vote `json:"data"`
}

// =============================================================================
// Relationship Response Types
// =============================================================================

// Generic relationship responses that return collections
type AnalysesResponse = url_relationships.AnalysesResponse
type CollectionsResponse = url_relationships.CollectionsResponse
type CommentsResponse = url_relationships.CommentsResponse
type CommunicatingFilesResponse = url_relationships.CommunicatingFilesResponse
type ContactedDomainsResponse = url_relationships.ContactedDomainsResponse
type ContactedIPsResponse = url_relationships.ContactedIPsResponse
type DownloadedFilesResponse = url_relationships.DownloadedFilesResponse
type EmbeddedJSFilesResponse = url_relationships.EmbeddedJSFilesResponse
type GraphsResponse = url_relationships.GraphsResponse
type RedirectingURLsResponse = url_relationships.RedirectingURLsResponse
type RedirectsToResponse = url_relationships.RedirectsToResponse
type ReferrerFilesResponse = url_relationships.ReferrerFilesResponse
type ReferrerURLsResponse = url_relationships.ReferrerURLsResponse
type RelatedCommentsResponse = url_relationships.RelatedCommentsResponse
type RelatedReferencesResponse = url_relationships.RelatedReferencesResponse
type RelatedThreatActorsResponse = url_relationships.RelatedThreatActorsResponse
type SubmissionsResponse = url_relationships.SubmissionsResponse
type UserVotesResponse = url_relationships.UserVotesResponse
type VotesRelationshipResponse = url_relationships.VotesResponse
type URLsRelatedByTrackerIDResponse = url_relationships.URLsRelatedByTrackerIDResponse

// Special relationship responses that return single objects
type LastServingIPAddressResponse = url_relationships.LastServingIPAddressResponse
type NetworkLocationResponse = url_relationships.NetworkLocationResponse

// =============================================================================
// Relationship Context Attributes
// =============================================================================

type EmbeddedJSFileContextAttributes = url_relationships.EmbeddedJSFileContextAttributes
type ReferrerURLContextAttributes = url_relationships.ReferrerURLContextAttributes
type RelatedCommentsContextAttributes = url_relationships.RelatedCommentsContextAttributes
type PostedInObject = url_relationships.PostedInObject
type RelatedReferencesContextAttributes = url_relationships.RelatedReferencesContextAttributes
type RelatedThreatActorsContextAttributes = url_relationships.RelatedThreatActorsContextAttributes
type RelatedFromObject = url_relationships.RelatedFromObject
type URLsRelatedByTrackerIDContextAttributes = url_relationships.URLsRelatedByTrackerIDContextAttributes
