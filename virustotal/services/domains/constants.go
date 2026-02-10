package domains

// API endpoints for domains
const (
	EndpointDomains = "/domains"
)

// Relationship names for domains (from VT API documentation)
const (
	RelationshipCAARecords                = "caa_records"
	RelationshipCNAMERecords              = "cname_records"
	RelationshipCollections               = "collections"
	RelationshipComments                  = "comments"
	RelationshipCommunicatingFiles        = "communicating_files"
	RelationshipDownloadedFiles           = "downloaded_files"
	RelationshipGraphs                    = "graphs"
	RelationshipHistoricalSSLCertificates = "historical_ssl_certificates"
	RelationshipHistoricalWhois           = "historical_whois"
	RelationshipImmediateParent           = "immediate_parent"
	RelationshipMXRecords                 = "mx_records"
	RelationshipNSRecords                 = "ns_records"
	RelationshipParent                    = "parent"
	RelationshipReferrerFiles             = "referrer_files"
	RelationshipRelatedComments           = "related_comments"
	RelationshipRelatedReferences         = "related_references"
	RelationshipRelatedThreatActors       = "related_threat_actors"
	RelationshipResolutions               = "resolutions"
	RelationshipSiblings                  = "siblings"
	RelationshipSOARecords                = "soa_records"
	RelationshipSubdomains                = "subdomains"
	RelationshipURLs                      = "urls"
	RelationshipUserVotes                 = "user_votes"
	RelationshipVotes                     = "votes"
)
