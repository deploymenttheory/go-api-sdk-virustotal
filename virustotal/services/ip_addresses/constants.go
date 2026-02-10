package ipaddresses

// API endpoints for IP addresses
const (
	EndpointIPAddresses = "/ip_addresses"
)

// Relationship names for IP addresses (from VT API documentation)
const (
	RelationshipCollections               = "collections"
	RelationshipComments                  = "comments"
	RelationshipCommunicatingFiles        = "communicating_files"
	RelationshipDownloadedFiles           = "downloaded_files"
	RelationshipGraphs                    = "graphs"
	RelationshipHistoricalSSLCertificates = "historical_ssl_certificates"
	RelationshipHistoricalWhois           = "historical_whois"
	RelationshipRelatedComments           = "related_comments"
	RelationshipRelatedReferences         = "related_references"
	RelationshipRelatedThreatActors       = "related_threat_actors"
	RelationshipReferrerFiles             = "referrer_files"
	RelationshipResolutions               = "resolutions"
	RelationshipURLs                      = "urls"
	RelationshipUserVotes                 = "user_votes"
	RelationshipVotes                     = "votes"
)
