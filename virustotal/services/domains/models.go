package domains

// =============================================================================
// Domain Report Models
// =============================================================================

// Domain represents a domain object from VirusTotal API
// Matches the schema from API v3 documentation
type Domain struct {
	Type       string           `json:"type"`       // Object type (always "domain")
	ID         string           `json:"id"`         // Domain name
	Links      Links            `json:"links"`      // Object links
	Attributes DomainAttributes `json:"attributes"` // Domain attributes
}

// Links represents the links section of an object
type Links struct {
	Self string `json:"self"` // URL to this object
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
	OCSP   []string `json:"ocsp,omitempty"`
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
	Type       string           `json:"type"`  // Object type (e.g., "analysis")
	ID         string           `json:"id"`    // Analysis ID
	Links      Links            `json:"links"` // Object links
	Attributes RescanAttributes `json:"attributes"`
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

// RelatedObject represents an object related to a domain
type RelatedObject struct {
	Type              string         `json:"type"`                         // Object type (e.g., "file", "url")
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
// Votes Models
// =============================================================================

// VotesResponse represents the response for votes on a domain
type VotesResponse struct {
	Data  []Vote       `json:"data"`
	Links RelatedLinks `json:"links,omitempty"`
}

// Vote represents a vote on a domain
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

// =============================================================================
// DNS Resolution Models
// =============================================================================

// ResolutionResponse represents the response for a DNS resolution object
type ResolutionResponse struct {
	Data Resolution `json:"data"`
}

// Resolution represents a DNS resolution object
type Resolution struct {
	Type       string               `json:"type"`       // Object type ("resolution")
	ID         string               `json:"id"`         // Resolution ID (domain-ip)
	Links      Links                `json:"links"`      // Object links
	Attributes ResolutionAttributes `json:"attributes"` // Resolution attributes
}

// ResolutionAttributes contains the attributes of a DNS resolution
type ResolutionAttributes struct {
	Date      int64  `json:"date"`               // Unix timestamp
	IPAddress string `json:"ip_address"`         // IP address
	HostName  string `json:"host_name"`          // Domain/hostname
	Resolver  string `json:"resolver,omitempty"` // DNS resolver
}
