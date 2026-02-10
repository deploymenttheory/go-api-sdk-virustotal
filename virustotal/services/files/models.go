package files

import "io"

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
	Type  string `json:"type"` // "analysis"
	ID    string `json:"id"`   // Analysis ID
	Links Links  `json:"links"`
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
	Type       string         `json:"type"`       // Object type (always "file")
	ID         string         `json:"id"`         // File hash (SHA256)
	Links      Links          `json:"links"`      // Object links
	Attributes FileAttributes `json:"attributes"` // File attributes
}

// Links represents the links section of an object
type Links struct {
	Self string `json:"self"` // URL to this object
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
	Links      Links                     `json:"links"`      // Object links
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

// RelatedObjectsResponse represents the response for related objects
type RelatedObjectsResponse struct {
	Data  []RelatedObject `json:"data"`
	Links RelatedLinks    `json:"links,omitempty"`
	Meta  Meta            `json:"meta,omitempty"`
}

// RelatedObject represents an object related to a file
type RelatedObject struct {
	Type              string         `json:"type"`                         // Object type (e.g., "domain", "url")
	ID                string         `json:"id"`                           // Object ID
	Links             Links          `json:"links"`                        // Object links
	Attributes        map[string]any `json:"attributes"`                   // Object attributes (varies by type)
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
// Sigma Rules Models
// =============================================================================

// SigmaRuleResponse represents the response for a Sigma rule object
type SigmaRuleResponse struct {
	Data SigmaRule `json:"data"`
}

// SigmaRule represents a crowdsourced Sigma rule
type SigmaRule struct {
	Type       string              `json:"type"`       // Object type ("sigma_rule")
	ID         string              `json:"id"`         // Rule ID
	Links      Links               `json:"links"`      // Object links
	Attributes SigmaRuleAttributes `json:"attributes"` // Rule attributes
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
	Type       string                `json:"type"`       // Object type ("yara_ruleset")
	ID         string                `json:"id"`         // Ruleset ID
	Links      Links                 `json:"links"`      // Object links
	Attributes YARARulesetAttributes `json:"attributes"` // Ruleset attributes
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

// VotesResponse represents the response for votes on a file
type VotesResponse struct {
	Data  []Vote       `json:"data"`
	Links RelatedLinks `json:"links,omitempty"`
}

// Vote represents a vote on a file
type Vote struct {
	Attributes VoteAttributes `json:"attributes"`
	ID         string         `json:"id"`
	Links      Links          `json:"links"`
	Type       string         `json:"type"` // "vote"
}

// VoteAttributes contains the attributes of a vote
type VoteAttributes struct {
	Date    int64  `json:"date"`    // Unix timestamp
	Value   int    `json:"value"`   // Vote value (1 or -1)
	Verdict string `json:"verdict"` // "harmless" or "malicious"
}

// GetVotesOptions contains optional parameters for votes requests
type GetVotesOptions struct {
	Limit  int    // Number of items per page (default 10, max 40)
	Cursor string // Continuation cursor for pagination
}

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
