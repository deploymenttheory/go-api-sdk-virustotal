package ipaddresses

// IPAddress represents an IP address object from VirusTotal API
// Matches the schema from API v3 documentation
type IPAddress struct {
	Type       string              `json:"type"`       // Object type (always "ip_address")
	ID         string              `json:"id"`         // IP address
	Links      Links               `json:"links"`      // Object links
	Attributes IPAddressAttributes `json:"attributes"` // IP address attributes
}

// Links represents the links section of an object
type Links struct {
	Self string `json:"self"` // URL to this object
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
