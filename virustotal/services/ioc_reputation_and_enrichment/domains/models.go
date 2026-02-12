package domains

import (
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models"
	domain_relationships "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models/relationships/domains"
)

// =============================================================================
// Domain Report Models
// =============================================================================

// Domain represents a domain object from VirusTotal API
// Matches the schema from API v3 documentation
type Domain struct {
	Type       string                    `json:"type"`       // Object type (always "domain")
	ID         string                    `json:"id"`         // Domain name
	Links      shared_models.ObjectLinks `json:"links"`      // Object links
	Attributes DomainAttributes          `json:"attributes"` // Domain attributes
}

// DomainAttributes contains the attributes of a domain
type DomainAttributes struct {
	// DNS Information
	Categories map[string]string `json:"categories,omitempty"` // Categorization from various vendors

	// Analysis results
	LastAnalysisDate    int64                   `json:"last_analysis_date,omitempty"`    // Unix timestamp
	LastAnalysisResults map[string]EngineResult `json:"last_analysis_results,omitempty"` // Detection results per engine
	LastAnalysisStats   LastAnalysisStats       `json:"last_analysis_stats,omitempty"`

	// DNS Records
	LastDNSRecords     []DNSRecord `json:"last_dns_records,omitempty"`
	LastDNSRecordsDate int64       `json:"last_dns_records_date,omitempty"` // Unix timestamp

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

	// Domain registration
	Registrar       string          `json:"registrar,omitempty"`
	CreationDate    int64           `json:"creation_date,omitempty"`    // Unix timestamp
	ExpirationDate  int64           `json:"expiration_date,omitempty"`  // Unix timestamp
	LastUpdateDate  int64           `json:"last_update_date,omitempty"` // Unix timestamp
	Nameservers     []string        `json:"name_servers,omitempty"`     // Authoritative name servers
	JARMHash        string          `json:"jarm,omitempty"`             // TLS fingerprint
	PopularityRanks map[string]Rank `json:"popularity_ranks,omitempty"`

	// Metadata
	LastModificationDate int64 `json:"last_modification_date,omitempty"` // Unix timestamp
}

// DNSRecord represents a DNS record for a domain
type DNSRecord struct {
	Type  string `json:"type"`  // Record type (A, AAAA, MX, NS, etc.)
	Value string `json:"value"` // Record value
	TTL   int    `json:"ttl,omitempty"`
}

// Rank represents popularity rank from a service
type Rank struct {
	Rank      int   `json:"rank"`
	Timestamp int64 `json:"timestamp,omitempty"`
}

// EngineResult represents the result from a single security engine
type EngineResult struct {
	Category   string `json:"category"`    // "harmless", "malicious", "suspicious", "undetected", "timeout"
	EngineName string `json:"engine_name"` // Name of the security engine
	Method     string `json:"method"`      // Detection method (e.g., "blacklist")
	Result     string `json:"result"`      // Result description (e.g., "clean", "malicious")
}

// LastAnalysisStats contains the detection statistics
type LastAnalysisStats struct {
	Harmless   int `json:"harmless,omitempty"`
	Malicious  int `json:"malicious,omitempty"`
	Suspicious int `json:"suspicious,omitempty"`
	Undetected int `json:"undetected,omitempty"`
	Timeout    int `json:"timeout,omitempty"`
}

// HTTPSCertificate represents the last HTTPS certificate seen for the domain
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
	SubjectAlternativeName []string               `json:"subject_alternative_name,omitempty"`
	AuthorityKeyIdentifier AuthorityKeyIdentifier `json:"authority_key_identifier,omitempty"`
	SubjectKeyIdentifier   string                 `json:"subject_key_identifier,omitempty"`
	KeyUsage               []string               `json:"key_usage,omitempty"`
	ExtendedKeyUsage       []string               `json:"extended_key_usage,omitempty"`
	CertificatePolicies    []string               `json:"certificate_policies,omitempty"`
	CRLDistributionPoints  []string               `json:"crl_distribution_points,omitempty"`
	CAInformationAccess    CAInformationAccess    `json:"ca_information_access,omitempty"`
	BasicConstraints       BasicConstraints       `json:"basic_constraints,omitempty"`
}

// AuthorityKeyIdentifier represents the authority key identifier extension
type AuthorityKeyIdentifier struct {
	Keyid string `json:"keyid,omitempty"`
}

// CAInformationAccess represents CA information access extension
type CAInformationAccess struct {
	OCSP   any      `json:"ocsp,omitempty"` // Can be string or []string
	Issuer []string `json:"ca_issuers,omitempty"`
}

// BasicConstraints represents basic constraints extension
type BasicConstraints struct {
	CA bool `json:"ca,omitempty"`
}

// CertSubject represents a certificate subject or issuer
type CertSubject struct {
	C  string `json:"C,omitempty"`  // Country
	CN string `json:"CN,omitempty"` // Common Name
	L  string `json:"L,omitempty"`  // Locality
	O  string `json:"O,omitempty"`  // Organization
	OU string `json:"OU,omitempty"` // Organizational Unit
	ST string `json:"ST,omitempty"` // State/Province
}

// PublicKey represents a certificate's public key
type PublicKey struct {
	Algorithm string        `json:"algorithm,omitempty"` // e.g., "RSA", "EC"
	RSA       *RSAPublicKey `json:"rsa,omitempty"`
	EC        *ECPublicKey  `json:"ec,omitempty"`
}

// RSAPublicKey represents an RSA public key
type RSAPublicKey struct {
	KeySize  int    `json:"key_size,omitempty"` // Key size in bits
	Modulus  string `json:"modulus,omitempty"`  // Modulus (hex)
	Exponent string `json:"exponent,omitempty"` // Exponent (hex)
}

// ECPublicKey represents an elliptic curve public key
type ECPublicKey struct {
	Curve string `json:"curve,omitempty"` // Curve name
	Pub   string `json:"pub,omitempty"`   // Public key (hex)
}

// CertValidity represents the validity period of a certificate
type CertValidity struct {
	NotAfter  string `json:"not_after,omitempty"`  // Expiration date (ISO 8601)
	NotBefore string `json:"not_before,omitempty"` // Start date (ISO 8601)
}

// Votes represents the vote counts
type Votes struct {
	Harmless  int `json:"harmless,omitempty"`
	Malicious int `json:"malicious,omitempty"`
}

// DomainResponse is the response wrapper for domain requests
type DomainResponse struct {
	Data Domain `json:"data"`
}

// =============================================================================
// Domain Rescan Models
// =============================================================================

// RescanResponse represents the response from a rescan request
type RescanResponse struct {
	Data RescanData `json:"data"`
}

// RescanData contains the analysis information
type RescanData struct {
	Type       string                    `json:"type"`  // Object type (e.g., "analysis")
	ID         string                    `json:"id"`    // Analysis ID
	Links      shared_models.ObjectLinks `json:"links"` // Object links
	Attributes RescanAttributes          `json:"attributes"`
}

// RescanAttributes contains the attributes of a rescan analysis
type RescanAttributes struct {
	Date   int64       `json:"date"`   // Unix timestamp
	Status string      `json:"status"` // Status of the analysis (e.g., "queued")
	Stats  RescanStats `json:"stats,omitempty"`
}

// RescanStats contains the statistics of the rescan
type RescanStats struct {
	Harmless   int `json:"harmless,omitempty"`
	Malicious  int `json:"malicious,omitempty"`
	Suspicious int `json:"suspicious,omitempty"`
	Undetected int `json:"undetected,omitempty"`
	Timeout    int `json:"timeout,omitempty"`
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
// Domain Relationships Models
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

// CAARecordsResponse represents the response from getting CAA records (VT Enterprise only)
type CAARecordsResponse = domain_relationships.CAARecordsResponse

// CNAMERecordsResponse represents the response from getting CNAME records (VT Enterprise only)
type CNAMERecordsResponse = domain_relationships.CNAMERecordsResponse

// CollectionsResponse represents the response from getting collections containing the domain
type CollectionsResponse = domain_relationships.CollectionsResponse

// CommentsResponse represents the response from getting comments on the domain
type CommentsResponse = domain_relationships.CommentsResponse

// CommunicatingFilesResponse represents the response from getting files that communicate with the domain
type CommunicatingFilesResponse = domain_relationships.CommunicatingFilesResponse

// DownloadedFilesResponse represents the response from getting files downloaded from the domain (VT Enterprise only)
type DownloadedFilesResponse = domain_relationships.DownloadedFilesResponse

// GraphsResponse represents the response from getting graphs containing the domain
type GraphsResponse = domain_relationships.GraphsResponse

// HistoricalSSLCertificatesResponse represents the response from getting historical SSL certificates
type HistoricalSSLCertificatesResponse = domain_relationships.HistoricalSSLCertificatesResponse

// HistoricalWhoisResponse represents the response from getting historical WHOIS information
type HistoricalWhoisResponse = domain_relationships.HistoricalWhoisResponse

// ImmediateParentResponse represents the response from getting the immediate parent domain
type ImmediateParentResponse = domain_relationships.ImmediateParentResponse

// MXRecordsResponse represents the response from getting MX records (VT Enterprise only)
type MXRecordsResponse = domain_relationships.MXRecordsResponse

// NSRecordsResponse represents the response from getting NS records (VT Enterprise only)
type NSRecordsResponse = domain_relationships.NSRecordsResponse

// ParentResponse represents the response from getting the top parent domain
type ParentResponse = domain_relationships.ParentResponse

// ReferrerFilesResponse represents the response from getting files containing the domain
type ReferrerFilesResponse = domain_relationships.ReferrerFilesResponse

// RelatedCommentsResponse represents the response from getting comments in related objects
type RelatedCommentsResponse = domain_relationships.RelatedCommentsResponse

// RelatedReferencesResponse represents the response from getting related references (VT Enterprise only)
type RelatedReferencesResponse = domain_relationships.RelatedReferencesResponse

// RelatedThreatActorsResponse represents the response from getting related threat actors (VT Enterprise only)
type RelatedThreatActorsResponse = domain_relationships.RelatedThreatActorsResponse

// ResolutionsResponse represents the response from getting DNS resolutions
type ResolutionsResponse = domain_relationships.ResolutionsResponse

// SiblingsResponse represents the response from getting sibling domains
type SiblingsResponse = domain_relationships.SiblingsResponse

// SOARecordsResponse represents the response from getting SOA records (VT Enterprise only)
type SOARecordsResponse = domain_relationships.SOARecordsResponse

// SubdomainsResponse represents the response from getting subdomains
type SubdomainsResponse = domain_relationships.SubdomainsResponse

// URLsResponse represents the response from getting URLs under the domain (VT Enterprise only)
type URLsResponse = domain_relationships.URLsResponse

// UserVotesResponse represents the response from getting current user's votes
type UserVotesResponse = domain_relationships.UserVotesResponse

// =============================================================================
// Relationship Context Attributes
// =============================================================================

// CAARecordContextAttributes contains context attributes for CAA records
type CAARecordContextAttributes = domain_relationships.CAARecordContextAttributes

// CNAMERecordContextAttributes contains context attributes for CNAME records
type CNAMERecordContextAttributes = domain_relationships.CNAMERecordContextAttributes

// MXRecordContextAttributes contains context attributes for MX records
type MXRecordContextAttributes = domain_relationships.MXRecordContextAttributes

// NSRecordContextAttributes contains context attributes for NS records
type NSRecordContextAttributes = domain_relationships.NSRecordContextAttributes

// SOARecordContextAttributes contains context attributes for SOA records
type SOARecordContextAttributes = domain_relationships.SOARecordContextAttributes

// HistoricalSSLCertificatesContextAttributes contains context attributes for historical SSL certificates
type HistoricalSSLCertificatesContextAttributes = domain_relationships.HistoricalSSLCertificatesContextAttributes

// RelatedCommentsContextAttributes contains context attributes for related comments
type RelatedCommentsContextAttributes = domain_relationships.RelatedCommentsContextAttributes

// PostedInObject specifies the object where a comment was posted
type PostedInObject = domain_relationships.PostedInObject

// RelatedReferencesContextAttributes contains context attributes for related references
type RelatedReferencesContextAttributes = domain_relationships.RelatedReferencesContextAttributes

// RelatedThreatActorsContextAttributes contains context attributes for related threat actors
type RelatedThreatActorsContextAttributes = domain_relationships.RelatedThreatActorsContextAttributes

// RelatedFromObject specifies an object from which something is related
type RelatedFromObject = domain_relationships.RelatedFromObject

// =============================================================================
// Votes Models
// =============================================================================

// VotesResponse represents the response for votes on a domain
// Note: This is a custom response type specific to GetVotesOnDomain endpoint
type VotesResponse struct {
	Data  []Vote              `json:"data"`
	Links shared_models.Links `json:"links,omitempty"`
	Meta  *shared_models.Meta `json:"meta,omitempty"`
}

// Vote represents a vote on a domain
type Vote struct {
	Type       string                     `json:"type"`                 // Object type (always "vote")
	ID         string                     `json:"id"`                   // Vote ID
	Links      *shared_models.ObjectLinks `json:"links,omitempty"`      // Vote links
	Attributes VoteAttributes             `json:"attributes,omitempty"` // Vote attributes
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

// =============================================================================
// DNS Resolution Models
// =============================================================================

// ResolutionResponse represents the response for a DNS resolution object
type ResolutionResponse struct {
	Data Resolution `json:"data"`
}

// Resolution represents a DNS resolution object
type Resolution struct {
	Type       string                    `json:"type"`       // Object type ("resolution")
	ID         string                    `json:"id"`         // Resolution ID (domain-ip)
	Links      shared_models.ObjectLinks `json:"links"`      // Object links
	Attributes ResolutionAttributes      `json:"attributes"` // Resolution attributes
}

// ResolutionAttributes contains the attributes of a DNS resolution
type ResolutionAttributes struct {
	Date      int64  `json:"date"`               // Unix timestamp
	IPAddress string `json:"ip_address"`         // IP address
	HostName  string `json:"host_name"`          // Domain/hostname
	Resolver  string `json:"resolver,omitempty"` // DNS resolver
}
