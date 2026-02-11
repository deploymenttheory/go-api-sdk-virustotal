package domains

// Domain relationship constants from VirusTotal API documentation
// https://docs.virustotal.com/reference/domains-object#relationships
const (
	// RelationshipCAARecords returns the domain's CAA records (VT Enterprise only)
	RelationshipCAARecords = "caa_records"

	// RelationshipCNAMERecords returns the domain's CNAME records (VT Enterprise only)
	RelationshipCNAMERecords = "cname_records"

	// RelationshipCollections returns collections containing this domain
	RelationshipCollections = "collections"

	// RelationshipComments returns community comments about the domain
	RelationshipComments = "comments"

	// RelationshipCommunicatingFiles returns files that communicate with the domain
	RelationshipCommunicatingFiles = "communicating_files"

	// RelationshipDownloadedFiles returns files downloaded from the domain (VT Enterprise only)
	RelationshipDownloadedFiles = "downloaded_files"

	// RelationshipGraphs returns graphs containing the domain
	RelationshipGraphs = "graphs"

	// RelationshipHistoricalSSLCertificates returns SSL certificates associated with the domain
	RelationshipHistoricalSSLCertificates = "historical_ssl_certificates"

	// RelationshipHistoricalWhois returns WHOIS information for the domain
	RelationshipHistoricalWhois = "historical_whois"

	// RelationshipImmediateParent returns the domain's immediate parent
	RelationshipImmediateParent = "immediate_parent"

	// RelationshipMXRecords returns the domain's MX records (VT Enterprise only)
	RelationshipMXRecords = "mx_records"

	// RelationshipNSRecords returns the domain's NS records (VT Enterprise only)
	RelationshipNSRecords = "ns_records"

	// RelationshipParent returns the domain's top parent
	RelationshipParent = "parent"

	// RelationshipReferrerFiles returns files containing the domain
	RelationshipReferrerFiles = "referrer_files"

	// RelationshipRelatedComments returns comments in the domain's related objects
	RelationshipRelatedComments = "related_comments"

	// RelationshipRelatedReferences returns references related to the domain (VT Enterprise only)
	RelationshipRelatedReferences = "related_references"

	// RelationshipRelatedThreatActors returns threat actors related to the domain (VT Enterprise only)
	RelationshipRelatedThreatActors = "related_threat_actors"

	// RelationshipResolutions returns DNS resolutions for the domain
	RelationshipResolutions = "resolutions"

	// RelationshipSiblings returns the domain's sibling domains
	RelationshipSiblings = "siblings"

	// RelationshipSOARecords returns the domain's SOA records (VT Enterprise only)
	RelationshipSOARecords = "soa_records"

	// RelationshipSubdomains returns the domain's subdomains
	RelationshipSubdomains = "subdomains"

	// RelationshipURLs returns URLs under this domain (VT Enterprise only)
	RelationshipURLs = "urls"

	// RelationshipUserVotes returns current user's votes
	RelationshipUserVotes = "user_votes"

	// RelationshipVotes returns all votes on the domain
	RelationshipVotes = "votes"
)
