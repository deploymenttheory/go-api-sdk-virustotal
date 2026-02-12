package ipaddresses

import (
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models"
	ip_relationships "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models/relationships/ip_addresses"
)

// =============================================================================
// IP Address Report Models
// =============================================================================

// IPAddress represents an IP address object from VirusTotal API
// Matches the schema from API v3 documentation
type IPAddress struct {
	Type       string                  `json:"type"`       // Object type (always "ip_address")
	ID         string                  `json:"id"`         // IP address
	Links      shared_models.ObjectLinks `json:"links"`      // Object links
	Attributes IPAddressAttributes     `json:"attributes"` // IP address attributes
}

// IPAddressAttributes contains the attributes of an IP address
type IPAddressAttributes struct {
	// Network information
	Network                  string `json:"network,omitempty"`
	ASN                      int    `json:"asn,omitempty"`
	ASOwner                  string `json:"as_owner,omitempty"`
	Country                  string `json:"country,omitempty"`
	Continent                string `json:"continent,omitempty"`
	RegionalInternetRegistry string `json:"regional_internet_registry,omitempty"`

	// TLS/SSL fingerprint
	JARM string `json:"jarm,omitempty"`

	// Analysis results
	LastAnalysisDate    int64                   `json:"last_analysis_date,omitempty"`    // Unix timestamp
	LastAnalysisResults map[string]EngineResult `json:"last_analysis_results,omitempty"` // Detection results per engine
	LastAnalysisStats   LastAnalysisStats       `json:"last_analysis_stats,omitempty"`

	// HTTPS Certificate information
	LastHTTPSCertificate     *HTTPSCertificate `json:"last_https_certificate,omitempty"`
	LastHTTPSCertificateDate int64             `json:"last_https_certificate_date,omitempty"` // Unix timestamp

	// Reputation and votes
	Reputation int      `json:"reputation,omitempty"`
	TotalVotes Votes    `json:"total_votes,omitempty"`
	Tags       []string `json:"tags,omitempty"`

	// WHOIS information
	Whois     string `json:"whois,omitempty"`
	WhoisDate int64  `json:"whois_date,omitempty"` // Unix timestamp

	// Metadata
	LastModificationDate int64 `json:"last_modification_date,omitempty"` // Unix timestamp
}

// EngineResult represents the result from a single security engine
type EngineResult struct {
	Category   string `json:"category"`    // "harmless", "malicious", "suspicious", "undetected", "timeout"
	EngineName string `json:"engine_name"` // Name of the security engine
	Method     string `json:"method"`      // Detection method (e.g., "blacklist")
	Result     string `json:"result"`      // Result description (e.g., "clean", "malicious")
}

// AnalysisResult represents the result from a single security engine
type AnalysisResult struct {
	Category   string `json:"category"`    // "harmless", "malicious", "suspicious", "undetected"
	EngineName string `json:"engine_name"` // Name of the security engine
	Method     string `json:"method"`      // Detection method (e.g., "blacklist")
	Result     string `json:"result"`      // Result description (e.g., "clean", "malware")
}

// LastAnalysisStats contains the detection statistics
type LastAnalysisStats struct {
	Harmless   int `json:"harmless,omitempty"`
	Malicious  int `json:"malicious,omitempty"`
	Suspicious int `json:"suspicious,omitempty"`
	Undetected int `json:"undetected,omitempty"`
	Timeout    int `json:"timeout,omitempty"`
}

// HTTPSCertificate represents the last HTTPS certificate seen for the IP
type HTTPSCertificate struct {
	CertSignature      CertSignature  `json:"cert_signature,omitempty"`
	Extensions         CertExtensions `json:"extensions,omitempty"`
	Issuer             CertSubject    `json:"issuer,omitempty"`
	PublicKey          PublicKey      `json:"public_key,omitempty"`
	SerialNumber       string         `json:"serial_number,omitempty"`
	SignatureAlgorithm string         `json:"signature_algorithm,omitempty"`
	Size               int            `json:"size,omitempty"`
	Subject            CertSubject    `json:"subject,omitempty"`
	Thumbprint         string         `json:"thumbprint,omitempty"`
	ThumbprintSHA256   string         `json:"thumbprint_sha256,omitempty"`
	Validity           CertValidity   `json:"validity,omitempty"`
	Version            string         `json:"version,omitempty"`
}

// CertSignature represents the certificate signature
type CertSignature struct {
	Signature          string `json:"signature,omitempty"`
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`
}

// CertExtensions represents certificate extensions
type CertExtensions struct {
	CA                     bool              `json:"CA,omitempty"`
	AuthorityKeyIdentifier map[string]string `json:"authority_key_identifier,omitempty"`
	CAInformationAccess    map[string]string `json:"ca_information_access,omitempty"`
	CertificatePolicies    []string          `json:"certificate_policies,omitempty"`
	ExtendedKeyUsage       []string          `json:"extended_key_usage,omitempty"`
	KeyUsage               []string          `json:"key_usage,omitempty"`
	SubjectAlternativeName []string          `json:"subject_alternative_name,omitempty"`
	SubjectKeyIdentifier   string            `json:"subject_key_identifier,omitempty"`
}

// CertSubject represents certificate issuer or subject information
type CertSubject struct {
	C  string `json:"C,omitempty"`  // Country
	CN string `json:"CN,omitempty"` // Common Name
	O  string `json:"O,omitempty"`  // Organization
}

// PublicKey represents the certificate public key
type PublicKey struct {
	Algorithm string  `json:"algorithm,omitempty"`
	RSA       *RSAKey `json:"rsa,omitempty"`
}

// RSAKey represents RSA public key details
type RSAKey struct {
	Exponent string `json:"exponent,omitempty"`
	KeySize  int    `json:"key_size,omitempty"`
	Modulus  string `json:"modulus,omitempty"`
}

// CertValidity represents certificate validity period
type CertValidity struct {
	NotAfter  string `json:"not_after,omitempty"`
	NotBefore string `json:"not_before,omitempty"`
}

// Votes represents the voting statistics
type Votes struct {
	Harmless  int `json:"harmless,omitempty"`
	Malicious int `json:"malicious,omitempty"`
}

// IPAddressResponse represents the response from GET /ip_addresses/{ip}
type IPAddressResponse struct {
	Data IPAddress `json:"data"`
}

// RequestQueryOptions represents optional query parameters for IP address requests
type RequestQueryOptions struct {
	// Relationships to include in the response (comma-separated)
	// Examples: "comments", "resolutions", "historical_whois"
	Relationships string
}

// =============================================================================
// IP Address Rescan Models
// =============================================================================

// RescanIPAddressResponse represents the response from requesting an IP address rescan
type RescanIPAddressResponse struct {
	Data AnalysisData `json:"data"`
}

// AnalysisData contains the analysis information returned when requesting a rescan
type AnalysisData struct {
	Type  string       `json:"type"`  // "analysis"
	ID    string       `json:"id"`    // Analysis ID
	Links AnalysisLink `json:"links"` // Self link
}

// AnalysisLink contains the self-referencing link for an analysis
type AnalysisLink struct {
	Self string `json:"self"` // URL to retrieve the analysis results
}

// =============================================================================
// Add Comment to an IP Address Models
// =============================================================================

// AddCommentRequest represents a request to add a comment to an IP address
type AddCommentRequest struct {
	Data CommentData `json:"data"`
}

// CommentData contains the comment data to be posted
type CommentData struct {
	Type       string            `json:"type"`       // "comment"
	Attributes CommentAttributes `json:"attributes"` // Comment attributes
}

// CommentAttributes contains the comment text
type CommentAttributes struct {
	Text string `json:"text"` // Comment text (words starting with # become tags)
}

// AddCommentResponse represents the response from adding a comment
type AddCommentResponse struct {
	Data Comment `json:"data"`
}

// Comment represents a comment object returned from the API
type Comment struct {
	Type       string                    `json:"type"`       // "comment"
	ID         string                    `json:"id"`         // Comment ID
	Links      shared_models.ObjectLinks `json:"links"`      // Comment links
	Attributes CommentResponseAttributes `json:"attributes"` // Comment attributes
}

// CommentResponseAttributes contains the full comment information
type CommentResponseAttributes struct {
	Text       string   `json:"text"`        // Comment text
	Date       int64    `json:"date"`        // Creation date (Unix timestamp)
	Tags       []string `json:"tags"`        // Tags extracted from text (words starting with #)
	HTMLText   string   `json:"html"`        // HTML-formatted text
	Votes      Votes    `json:"votes"`       // Vote counts
	VotesCount int      `json:"votes_count"` // Total vote count
}

// =============================================================================
// IP Address Relationships Models
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

// CollectionsResponse represents collections containing this IP address
type CollectionsResponse = ip_relationships.CollectionsResponse

// CommentsResponse represents comments posted on the IP address
type CommentsResponse = ip_relationships.CommentsResponse

// CommunicatingFilesResponse represents files that communicate with the IP address
type CommunicatingFilesResponse = ip_relationships.CommunicatingFilesResponse

// DownloadedFilesResponse represents files downloaded from the IP address (VT Enterprise only)
type DownloadedFilesResponse = ip_relationships.DownloadedFilesResponse

// GraphsResponse represents graphs including the IP address
type GraphsResponse = ip_relationships.GraphsResponse

// HistoricalSSLCertificatesResponse represents SSL certificates associated with the IP
type HistoricalSSLCertificatesResponse = ip_relationships.HistoricalSSLCertificatesResponse

// HistoricalWhoisResponse represents WHOIS information for the IP address
type HistoricalWhoisResponse = ip_relationships.HistoricalWhoisResponse

// RelatedCommentsResponse represents community posted comments in the IP's related objects
type RelatedCommentsResponse = ip_relationships.RelatedCommentsResponse

// RelatedReferencesResponse represents references related to the IP address (VT Enterprise only)
type RelatedReferencesResponse = ip_relationships.RelatedReferencesResponse

// RelatedThreatActorsResponse represents threat actors related to the IP address (VT Enterprise only)
type RelatedThreatActorsResponse = ip_relationships.RelatedThreatActorsResponse

// ReferrerFilesResponse represents files containing the IP address
type ReferrerFilesResponse = ip_relationships.ReferrerFilesResponse

// ResolutionsResponse represents IP address' resolutions
type ResolutionsResponse = ip_relationships.ResolutionsResponse

// URLsResponse represents URLs related to the IP address (VT Enterprise only)
type URLsResponse = ip_relationships.URLsResponse

// UserVotesResponse represents votes for the current user
type UserVotesResponse = ip_relationships.UserVotesResponse

// =============================================================================
// Relationship Context Attributes
// =============================================================================

// HistoricalSSLCertificatesContextAttributes represents context attributes for SSL certificates
type HistoricalSSLCertificatesContextAttributes = ip_relationships.HistoricalSSLCertificatesContextAttributes

// RelatedCommentsContextAttributes represents context attributes for related comments
type RelatedCommentsContextAttributes = ip_relationships.RelatedCommentsContextAttributes

// PostedInObject represents the object where a comment was posted
type PostedInObject = ip_relationships.PostedInObject

// RelatedReferencesContextAttributes represents context attributes for related references (VT Enterprise only)
type RelatedReferencesContextAttributes = ip_relationships.RelatedReferencesContextAttributes

// RelatedFromObject represents an object that a reference is related from
type RelatedFromObject = ip_relationships.RelatedFromObject

// RelatedThreatActorsContextAttributes represents context attributes for related threat actors (VT Enterprise only)
type RelatedThreatActorsContextAttributes = ip_relationships.RelatedThreatActorsContextAttributes

// =============================================================================
// Votes Models
// =============================================================================

// VotesResponse represents the response from getting votes on an IP address
type VotesResponse struct {
	Data  []Vote          `json:"data"`            // Array of votes
	Links shared_models.Links `json:"links,omitempty"` // Pagination links
	Meta  *shared_models.Meta `json:"meta,omitempty"`  // Metadata including cursor
}

// Vote represents a vote on an IP address
type Vote struct {
	Type       string                     `json:"type"`                 // Object type (always "vote")
	ID         string                     `json:"id"`                   // Vote ID
	Links      *shared_models.ObjectLinks `json:"links,omitempty"`      // Vote links
	Attributes VoteAttributes             `json:"attributes,omitempty"` // Vote attributes
}

// VoteAttributes contains the attributes of a vote
type VoteAttributes struct {
	Date    int64  `json:"date"`    // Unix timestamp when the vote was cast
	Value   int    `json:"value"`   // Vote value (1 for harmless, -1 for malicious)
	Verdict string `json:"verdict"` // Verdict ("harmless" or "malicious")
}

// GetVotesOptions contains query parameters for votes requests
type GetVotesOptions struct {
	Limit  int    // Maximum number of votes to return per page
	Cursor string // Pagination cursor - if provided, returns single page only (manual pagination mode)
}

// AddVoteRequest represents the request body for adding a vote to an IP address
type AddVoteRequest struct {
	Data VoteData `json:"data"`
}

// VoteData represents the vote data in the request
type VoteData struct {
	Type       string             `json:"type"`       // Object type (always "vote")
	Attributes VoteDataAttributes `json:"attributes"` // Vote attributes
}

// VoteDataAttributes contains the attributes for adding a vote
type VoteDataAttributes struct {
	Verdict string `json:"verdict"` // Vote verdict ("harmless" or "malicious")
}

// AddVoteResponse represents the response from adding a vote
type AddVoteResponse struct {
	Data Vote `json:"data"` // The created vote object
}
