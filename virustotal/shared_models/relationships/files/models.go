package files

import "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models"

// =============================================================================
// Generic Relationship Response Types (Type Aliases)
// =============================================================================

// AnalysesResponse represents the response from getting analyses for the file (VT Enterprise only)
type AnalysesResponse = shared_models.RelatedObjectsResponse

// BehavioursResponse represents the response from getting behaviour reports
type BehavioursResponse = shared_models.RelatedObjectsResponse

// BundledFilesResponse represents the response from getting files bundled within the file
type BundledFilesResponse = shared_models.RelatedObjectsResponse

// CarbonBlackChildrenResponse represents the response from getting Carbon Black children (VT Enterprise only)
type CarbonBlackChildrenResponse = shared_models.RelatedObjectsResponse

// CarbonBlackParentsResponse represents the response from getting Carbon Black parents (VT Enterprise only)
type CarbonBlackParentsResponse = shared_models.RelatedObjectsResponse

// CollectionsResponse represents the response from getting collections containing the file
type CollectionsResponse = shared_models.RelatedObjectsResponse

// CommentsResponse represents the response from getting comments on the file
type CommentsResponse = shared_models.RelatedObjectsResponse

// CompressedParentsResponse represents the response from getting compressed parent files (VT Enterprise only)
type CompressedParentsResponse = shared_models.RelatedObjectsResponse

// ContactedDomainsResponse represents the response from getting domains contacted by the file
type ContactedDomainsResponse = shared_models.RelatedObjectsResponse

// ContactedIPsResponse represents the response from getting IP addresses contacted by the file
type ContactedIPsResponse = shared_models.RelatedObjectsResponse

// ContactedURLsResponse represents the response from getting URLs contacted by the file
type ContactedURLsResponse = shared_models.RelatedObjectsResponse

// DroppedFilesResponse represents the response from getting files dropped during execution
type DroppedFilesResponse = shared_models.RelatedObjectsResponse

// EmailAttachmentsResponse represents the response from getting email attachments (VT Enterprise only)
type EmailAttachmentsResponse = shared_models.RelatedObjectsResponse

// EmailParentsResponse represents the response from getting email parent files (VT Enterprise only)
type EmailParentsResponse = shared_models.RelatedObjectsResponse

// EmbeddedDomainsResponse represents the response from getting domains embedded in the file (VT Enterprise only)
type EmbeddedDomainsResponse = shared_models.RelatedObjectsResponse

// EmbeddedIPsResponse represents the response from getting IP addresses embedded in the file (VT Enterprise only)
type EmbeddedIPsResponse = shared_models.RelatedObjectsResponse

// EmbeddedURLsResponse represents the response from getting URLs embedded in the file (VT Enterprise only)
type EmbeddedURLsResponse = shared_models.RelatedObjectsResponse

// ExecutionParentsResponse represents the response from getting files that executed the file
type ExecutionParentsResponse = shared_models.RelatedObjectsResponse

// GraphsResponse represents the response from getting graphs containing the file
type GraphsResponse = shared_models.RelatedObjectsResponse

// ITWDomainsResponse represents the response from getting in-the-wild domains (VT Enterprise only)
type ITWDomainsResponse = shared_models.RelatedObjectsResponse

// ITWIPsResponse represents the response from getting in-the-wild IP addresses (VT Enterprise only)
type ITWIPsResponse = shared_models.RelatedObjectsResponse

// ITWURLsResponse represents the response from getting in-the-wild URLs (VT Enterprise only)
type ITWURLsResponse = shared_models.RelatedObjectsResponse

// MemoryPatternDomainsResponse represents the response from getting domains in memory pattern (VT Enterprise only)
type MemoryPatternDomainsResponse = shared_models.RelatedObjectsResponse

// MemoryPatternIPsResponse represents the response from getting IPs in memory pattern (VT Enterprise only)
type MemoryPatternIPsResponse = shared_models.RelatedObjectsResponse

// MemoryPatternURLsResponse represents the response from getting URLs in memory pattern (VT Enterprise only)
type MemoryPatternURLsResponse = shared_models.RelatedObjectsResponse

// OverlayChildrenResponse represents the response from getting overlay children files (VT Enterprise only)
type OverlayChildrenResponse = shared_models.RelatedObjectsResponse

// OverlayParentsResponse represents the response from getting overlay parent files (VT Enterprise only)
type OverlayParentsResponse = shared_models.RelatedObjectsResponse

// PCAPChildrenResponse represents the response from getting PCAP children files (VT Enterprise only)
type PCAPChildrenResponse = shared_models.RelatedObjectsResponse

// PCAPParentsResponse represents the response from getting PCAP parent files (VT Enterprise only)
type PCAPParentsResponse = shared_models.RelatedObjectsResponse

// PEResourceChildrenResponse represents the response from getting PE resource children files
type PEResourceChildrenResponse = shared_models.RelatedObjectsResponse

// PEResourceParentsResponse represents the response from getting PE resource parent files
type PEResourceParentsResponse = shared_models.RelatedObjectsResponse

// RelatedReferencesResponse represents the response from getting related references (VT Enterprise only)
type RelatedReferencesResponse = shared_models.RelatedObjectsResponse

// RelatedThreatActorsResponse represents the response from getting related threat actors (VT Enterprise only)
type RelatedThreatActorsResponse = shared_models.RelatedObjectsResponse

// ScreenshotsResponse represents the response from getting screenshots (VT Enterprise only)
type ScreenshotsResponse = shared_models.RelatedObjectsResponse

// SigmaAnalysisResponse represents the response from getting sigma analysis
type SigmaAnalysisResponse = shared_models.RelatedObjectsResponse

// SimilarFilesResponse represents the response from getting similar files (VT Enterprise only)
type SimilarFilesResponse = shared_models.RelatedObjectsResponse

// SubmissionsResponse represents the response from getting submissions (VT Enterprise only)
type SubmissionsResponse = shared_models.RelatedObjectsResponse

// URLsForEmbeddedJSResponse represents the response from getting URLs with embedded JS (VT Enterprise only)
type URLsForEmbeddedJSResponse = shared_models.RelatedObjectsResponse

// UserVotesResponse represents the response from getting current user's votes
type UserVotesResponse = shared_models.RelatedObjectsResponse

// VotesResponse represents the response from getting all votes on the file
type VotesResponse = shared_models.RelatedObjectsResponse

// =============================================================================
// Context Attributes for File Relationships
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
