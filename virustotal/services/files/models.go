package files

import (
	"io"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models"
	file_relationships "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models/relationships/files"
)

// =============================================================================
// File Upload Models
// =============================================================================

// UploadFileRequest contains the file data for upload
type UploadFileRequest struct {
	File             io.Reader
	Filename         string
	FileSize         int64                                                                                 // File size in bytes (required for progress tracking)
	Password         string                                                                                // Optional password for archive files
	ProgressCallback func(fieldName string, fileName string, bytesWritten int64, totalBytes int64) // Optional progress callback
}

// UploadFileResponse represents the response from uploading a file
type UploadFileResponse struct {
	Data AnalysisData `json:"data"`
}

// AnalysisData contains the analysis information
type AnalysisData struct {
	Type  string                    `json:"type"` // "analysis"
	ID    string                    `json:"id"`   // Analysis ID
	Links shared_models.ObjectLinks `json:"links"`
}

// =============================================================================
// Upload URL Models
// =============================================================================

// UploadURLResponse represents the response for getting an upload URL
type UploadURLResponse struct {
	Data string `json:"data"` // Upload URL
}

// =============================================================================
// File Report Models
// =============================================================================

// FileResponse represents the response wrapper for file requests
type FileResponse struct {
	Data File `json:"data"`
}

// File represents a file object from VirusTotal API
type File struct {
	Type       string                    `json:"type"`       // Object type (always "file")
	ID         string                    `json:"id"`         // File hash (SHA256)
	Links      shared_models.ObjectLinks `json:"links"`      // Object links
	Attributes FileAttributes            `json:"attributes"` // File attributes
}

// FileAttributes contains the attributes of a file
type FileAttributes struct {
	// File identification
	MD5    string `json:"md5,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256,omitempty"`

	// File metadata
	Type           string   `json:"type_description,omitempty"`
	TypeTag        string   `json:"type_tag,omitempty"`
	Size           int64    `json:"size,omitempty"`
	Names          []string `json:"names,omitempty"`
	MeaningfulName string   `json:"meaningful_name,omitempty"`
	TrID           []string `json:"trid,omitempty"`
	Magic          string   `json:"magic,omitempty"`
	Tags           []string `json:"tags,omitempty"`

	// Analysis results
	LastAnalysisDate    int64                   `json:"last_analysis_date,omitempty"`    // Unix timestamp
	LastAnalysisResults map[string]EngineResult `json:"last_analysis_results,omitempty"` // Detection results per engine
	LastAnalysisStats   LastAnalysisStats       `json:"last_analysis_stats,omitempty"`

	// Reputation and votes
	Reputation int   `json:"reputation,omitempty"`
	TotalVotes Votes `json:"total_votes,omitempty"`

	// Timestamps
	CreationDate         int64 `json:"creation_date,omitempty"`          // Unix timestamp
	FirstSubmissionDate  int64 `json:"first_submission_date,omitempty"`  // Unix timestamp
	LastSubmissionDate   int64 `json:"last_submission_date,omitempty"`   // Unix timestamp
	LastModificationDate int64 `json:"last_modification_date,omitempty"` // Unix timestamp

	// Submission and analysis metadata
	TimesSubmitted int    `json:"times_submitted,omitempty"`
	Ssdeep         string `json:"ssdeep,omitempty"`
	Tlsh           string `json:"tlsh,omitempty"`
	Vhash          string `json:"vhash,omitempty"`
	Authentihash   string `json:"authentihash,omitempty"`

	// Community and popularity
	PopularityRanks map[string]Rank `json:"popularity_ranks,omitempty"`

	// Executable-specific (PE files)
	PEInfo *PEInfo `json:"pe_info,omitempty"`

	// Signature information
	SignatureInfo *SignatureInfo `json:"signature_info,omitempty"`
}

// EngineResult represents the result from a single security engine
type EngineResult struct {
	Category   string `json:"category"`    // "harmless", "malicious", "suspicious", "undetected", "timeout", "type-unsupported", "failure"
	EngineName string `json:"engine_name"` // Name of the security engine
	Method     string `json:"method"`      // Detection method (e.g., "blacklist")
	Result     string `json:"result"`      // Result description (e.g., "clean", "malware name")
}

// LastAnalysisStats contains the detection statistics
type LastAnalysisStats struct {
	Harmless         int `json:"harmless,omitempty"`
	Malicious        int `json:"malicious,omitempty"`
	Suspicious       int `json:"suspicious,omitempty"`
	Undetected       int `json:"undetected,omitempty"`
	Timeout          int `json:"timeout,omitempty"`
	TypeUnsupported  int `json:"type-unsupported,omitempty"`
	Failure          int `json:"failure,omitempty"`
	ConfirmedTimeout int `json:"confirmed-timeout,omitempty"`
}

// Votes represents the vote counts
type Votes struct {
	Harmless  int `json:"harmless,omitempty"`
	Malicious int `json:"malicious,omitempty"`
}

// Rank represents popularity rank from a service
type Rank struct {
	Rank      int   `json:"rank"`
	Timestamp int64 `json:"timestamp,omitempty"`
}

// PEInfo represents portable executable information
type PEInfo struct {
	Imphash     string      `json:"imphash,omitempty"`
	MachineType int         `json:"machine_type,omitempty"`
	Timestamp   int64       `json:"timestamp,omitempty"`
	EntryPoint  int64       `json:"entry_point,omitempty"`
	Sections    []PESection `json:"sections,omitempty"`
	ImportList  []Import    `json:"import_list,omitempty"`
}

// PESection represents a PE file section
type PESection struct {
	Name           string  `json:"name,omitempty"`
	VirtualAddress int64   `json:"virtual_address,omitempty"`
	VirtualSize    int64   `json:"virtual_size,omitempty"`
	RawSize        int64   `json:"raw_size,omitempty"`
	Entropy        float64 `json:"entropy,omitempty"`
	MD5            string  `json:"md5,omitempty"`
}

// Import represents an imported DLL and its functions
type Import struct {
	LibraryName       string   `json:"library_name,omitempty"`
	ImportedFunctions []string `json:"imported_functions,omitempty"`
}

// SignatureInfo represents file signature information
type SignatureInfo struct {
	Verified      string `json:"verified,omitempty"`
	SignerDetails string `json:"signer details,omitempty"`
	Product       string `json:"product,omitempty"`
	Description   string `json:"description,omitempty"`
}

// =============================================================================
// File Rescan Models
// =============================================================================

// RescanResponse represents the response from a file rescan request
type RescanResponse struct {
	Data AnalysisData `json:"data"`
}

// =============================================================================
// Download URL Models
// =============================================================================

// DownloadURLResponse represents the response for getting a download URL
type DownloadURLResponse struct {
	Data string `json:"data"` // Download URL
}

// =============================================================================
// Comment Models
// =============================================================================

// AddCommentRequest represents the request body for adding a comment
type AddCommentRequest struct {
	Data CommentData `json:"data"`
}

// CommentData contains the comment information
type CommentData struct {
	Type       string            `json:"type"`       // Must be "comment"
	Attributes CommentAttributes `json:"attributes"` // Comment attributes
}

// CommentAttributes contains the comment text
type CommentAttributes struct {
	Text string `json:"text"` // Comment text
}

// AddCommentResponse represents the response when adding a comment
type AddCommentResponse struct {
	Data Comment `json:"data"`
}

// Comment represents a comment object
type Comment struct {
	Type       string                    `json:"type"`       // Object type ("comment")
	ID         string                    `json:"id"`         // Comment ID
	Links      shared_models.ObjectLinks `json:"links"`      // Object links
	Attributes CommentAttributesResponse `json:"attributes"` // Comment attributes
}

// CommentAttributesResponse contains the full comment attributes in a response
type CommentAttributesResponse struct {
	Date  int64    `json:"date"`           // Unix timestamp
	Text  string   `json:"text"`           // Comment text
	HTML  string   `json:"html,omitempty"` // HTML-formatted comment
	Tags  []string `json:"tags,omitempty"`
	Votes Votes    `json:"votes,omitempty"`
}

// =============================================================================
// Related Objects Models
// =============================================================================

// RelatedObjectsResponse represents the response from getting related objects
type RelatedObjectsResponse = shared_models.RelatedObjectsResponse

// RelatedObject represents a related object (file, URL, domain, etc.)
type RelatedObject = shared_models.RelatedObject

// RelatedObjectDescriptorsResponse represents the response from getting related object descriptors
type RelatedObjectDescriptorsResponse = shared_models.ObjectDescriptorsResponse

// ObjectDescriptor represents a lightweight descriptor of a related object (ID and type only)
type ObjectDescriptor = shared_models.ObjectDescriptor

// GetRelatedObjectsOptions contains query parameters for relationship requests
type GetRelatedObjectsOptions = shared_models.RelatedObjectsOptions

// =============================================================================
// Specific Relationship Response Types
// =============================================================================

// AnalysesResponse represents the response from getting analyses (VT Enterprise only)
type AnalysesResponse = file_relationships.AnalysesResponse

// BehavioursResponse represents the response from getting behaviour reports
type BehavioursResponse = file_relationships.BehavioursResponse

// BundledFilesResponse represents the response from getting bundled files
type BundledFilesResponse = file_relationships.BundledFilesResponse

// CarbonBlackChildrenResponse represents the response from getting Carbon Black children (VT Enterprise only)
type CarbonBlackChildrenResponse = file_relationships.CarbonBlackChildrenResponse

// CarbonBlackParentsResponse represents the response from getting Carbon Black parents (VT Enterprise only)
type CarbonBlackParentsResponse = file_relationships.CarbonBlackParentsResponse

// CollectionsResponse represents the response from getting collections
type CollectionsResponse = file_relationships.CollectionsResponse

// CommentsResponse represents the response from getting comments
type CommentsResponse = file_relationships.CommentsResponse

// CompressedParentsResponse represents the response from getting compressed parent files (VT Enterprise only)
type CompressedParentsResponse = file_relationships.CompressedParentsResponse

// ContactedDomainsResponse represents the response from getting contacted domains
type ContactedDomainsResponse = file_relationships.ContactedDomainsResponse

// ContactedIPsResponse represents the response from getting contacted IP addresses
type ContactedIPsResponse = file_relationships.ContactedIPsResponse

// ContactedURLsResponse represents the response from getting contacted URLs
type ContactedURLsResponse = file_relationships.ContactedURLsResponse

// DroppedFilesResponse represents the response from getting dropped files
type DroppedFilesResponse = file_relationships.DroppedFilesResponse

// EmailAttachmentsResponse represents the response from getting email attachments (VT Enterprise only)
type EmailAttachmentsResponse = file_relationships.EmailAttachmentsResponse

// EmailParentsResponse represents the response from getting email parent files (VT Enterprise only)
type EmailParentsResponse = file_relationships.EmailParentsResponse

// EmbeddedDomainsResponse represents the response from getting embedded domains (VT Enterprise only)
type EmbeddedDomainsResponse = file_relationships.EmbeddedDomainsResponse

// EmbeddedIPsResponse represents the response from getting embedded IP addresses (VT Enterprise only)
type EmbeddedIPsResponse = file_relationships.EmbeddedIPsResponse

// EmbeddedURLsResponse represents the response from getting embedded URLs (VT Enterprise only)
type EmbeddedURLsResponse = file_relationships.EmbeddedURLsResponse

// ExecutionParentsResponse represents the response from getting execution parent files
type ExecutionParentsResponse = file_relationships.ExecutionParentsResponse

// GraphsResponse represents the response from getting graphs
type GraphsResponse = file_relationships.GraphsResponse

// ITWDomainsResponse represents the response from getting in-the-wild domains (VT Enterprise only)
type ITWDomainsResponse = file_relationships.ITWDomainsResponse

// ITWIPsResponse represents the response from getting in-the-wild IP addresses (VT Enterprise only)
type ITWIPsResponse = file_relationships.ITWIPsResponse

// ITWURLsResponse represents the response from getting in-the-wild URLs (VT Enterprise only)
type ITWURLsResponse = file_relationships.ITWURLsResponse

// MemoryPatternDomainsResponse represents the response from getting memory pattern domains (VT Enterprise only)
type MemoryPatternDomainsResponse = file_relationships.MemoryPatternDomainsResponse

// MemoryPatternIPsResponse represents the response from getting memory pattern IPs (VT Enterprise only)
type MemoryPatternIPsResponse = file_relationships.MemoryPatternIPsResponse

// MemoryPatternURLsResponse represents the response from getting memory pattern URLs (VT Enterprise only)
type MemoryPatternURLsResponse = file_relationships.MemoryPatternURLsResponse

// OverlayChildrenResponse represents the response from getting overlay children files (VT Enterprise only)
type OverlayChildrenResponse = file_relationships.OverlayChildrenResponse

// OverlayParentsResponse represents the response from getting overlay parent files (VT Enterprise only)
type OverlayParentsResponse = file_relationships.OverlayParentsResponse

// PCAPChildrenResponse represents the response from getting PCAP children files (VT Enterprise only)
type PCAPChildrenResponse = file_relationships.PCAPChildrenResponse

// PCAPParentsResponse represents the response from getting PCAP parent files (VT Enterprise only)
type PCAPParentsResponse = file_relationships.PCAPParentsResponse

// PEResourceChildrenResponse represents the response from getting PE resource children files
type PEResourceChildrenResponse = file_relationships.PEResourceChildrenResponse

// PEResourceParentsResponse represents the response from getting PE resource parent files
type PEResourceParentsResponse = file_relationships.PEResourceParentsResponse

// RelatedReferencesResponse represents the response from getting related references (VT Enterprise only)
type RelatedReferencesResponse = file_relationships.RelatedReferencesResponse

// RelatedThreatActorsResponse represents the response from getting related threat actors (VT Enterprise only)
type RelatedThreatActorsResponse = file_relationships.RelatedThreatActorsResponse

// ScreenshotsResponse represents the response from getting screenshots (VT Enterprise only)
type ScreenshotsResponse = file_relationships.ScreenshotsResponse

// SigmaAnalysisResponseRelationship represents the response from getting sigma analysis
type SigmaAnalysisResponseRelationship = file_relationships.SigmaAnalysisResponse

// SimilarFilesResponse represents the response from getting similar files (VT Enterprise only)
type SimilarFilesResponse = file_relationships.SimilarFilesResponse

// SubmissionsResponse represents the response from getting submissions (VT Enterprise only)
type SubmissionsResponse = file_relationships.SubmissionsResponse

// URLsForEmbeddedJSResponse represents the response from getting URLs with embedded JS (VT Enterprise only)
type URLsForEmbeddedJSResponse = file_relationships.URLsForEmbeddedJSResponse

// UserVotesResponse represents the response from getting current user's votes
type UserVotesResponse = file_relationships.UserVotesResponse

// VotesResponseRelationship represents the response from getting all votes via relationships endpoint
type VotesResponseRelationship = file_relationships.VotesResponse

// =============================================================================
// Relationship Context Attributes
// =============================================================================

// RelatedCommentsContextAttributes contains context attributes for related comments
type RelatedCommentsContextAttributes = file_relationships.RelatedCommentsContextAttributes

// PostedInObject specifies the object where a comment was posted
type PostedInObject = file_relationships.PostedInObject

// RelatedReferencesContextAttributes contains context attributes for related references
type RelatedReferencesContextAttributes = file_relationships.RelatedReferencesContextAttributes

// RelatedThreatActorsContextAttributes contains context attributes for related threat actors
type RelatedThreatActorsContextAttributes = file_relationships.RelatedThreatActorsContextAttributes

// RelatedFromObject specifies an object from which something is related
type RelatedFromObject = file_relationships.RelatedFromObject

// =============================================================================
// Sigma Rules Models
// =============================================================================

// SigmaRuleResponse represents the response for a Sigma rule object
type SigmaRuleResponse struct {
	Data SigmaRule `json:"data"`
}

// SigmaRule represents a crowdsourced Sigma rule
type SigmaRule struct {
	Type       string                    `json:"type"`       // Object type ("sigma_rule")
	ID         string                    `json:"id"`         // Rule ID
	Links      shared_models.ObjectLinks `json:"links"`      // Object links
	Attributes SigmaRuleAttributes       `json:"attributes"` // Rule attributes
}

// SigmaRuleAttributes contains the attributes of a Sigma rule
type SigmaRuleAttributes struct {
	RuleName    string   `json:"rule_name,omitempty"`
	RuleSource  string   `json:"rule_source,omitempty"`
	RuleLevel   string   `json:"rule_level,omitempty"`
	RuleAuthor  string   `json:"rule_author,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	RuleID      string   `json:"rule_id,omitempty"`
}

// =============================================================================
// YARA Rulesets Models
// =============================================================================

// YARARulesetResponse represents the response for a YARA ruleset object
type YARARulesetResponse struct {
	Data YARARuleset `json:"data"`
}

// YARARuleset represents a crowdsourced YARA ruleset
type YARARuleset struct {
	Type       string                    `json:"type"`       // Object type ("yara_ruleset")
	ID         string                    `json:"id"`         // Ruleset ID
	Links      shared_models.ObjectLinks `json:"links"`      // Object links
	Attributes YARARulesetAttributes     `json:"attributes"` // Ruleset attributes
}

// YARARulesetAttributes contains the attributes of a YARA ruleset
type YARARulesetAttributes struct {
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Rules       []string `json:"rules,omitempty"`
	Source      string   `json:"source,omitempty"`
	Author      string   `json:"author,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// =============================================================================
// Votes Models
// =============================================================================

// VotesResponse represents the response for votes on a file from the /votes endpoint
type VotesResponse struct {
	Data  []Vote              `json:"data"`
	Links shared_models.Links `json:"links,omitempty"`
	Meta  *shared_models.Meta `json:"meta,omitempty"`
}

// Vote represents a vote on a file
type Vote struct {
	Type       string                     `json:"type"`       // Object type ("vote")
	ID         string                     `json:"id"`         // Vote ID
	Links      *shared_models.ObjectLinks `json:"links,omitempty"` // Vote links
	Attributes VoteAttributes             `json:"attributes"` // Vote attributes
}

// VoteAttributes contains the attributes of a vote
type VoteAttributes struct {
	Date    int64  `json:"date"`    // Unix timestamp
	Value   int    `json:"value"`   // Vote value (1 or -1)
	Verdict string `json:"verdict"` // "harmless" or "malicious"
}

// GetVotesOptions contains optional parameters for votes requests
type GetVotesOptions = shared_models.RelatedObjectsOptions

// =============================================================================
// Add Vote Models
// =============================================================================

// AddVoteRequest represents the request body for adding a vote
type AddVoteRequest struct {
	Data VoteData `json:"data"`
}

// VoteData contains the vote information
type VoteData struct {
	Type       string             `json:"type"`       // Must be "vote"
	Attributes VoteDataAttributes `json:"attributes"` // Vote attributes
}

// VoteDataAttributes contains the verdict for the vote
type VoteDataAttributes struct {
	Verdict string `json:"verdict"` // "harmless" or "malicious"
}

// AddVoteResponse represents the response when adding a vote
type AddVoteResponse struct {
	Data Vote `json:"data"`
}
