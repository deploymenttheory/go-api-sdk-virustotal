package ip_addresses

// Relationship names for IP addresses
// VirusTotal API docs: https://docs.virustotal.com/reference/ip-object#relationships
const (
	// Collections containing this IP address
	RelationshipCollections = "collections"

	// Comments posted on the IP address
	RelationshipComments = "comments"

	// Files that communicate with the IP address
	RelationshipCommunicatingFiles = "communicating_files"

	// Files downloaded from the IP address (VT Enterprise only)
	RelationshipDownloadedFiles = "downloaded_files"

	// Graphs including the IP address
	RelationshipGraphs = "graphs"

	// SSL certificates associated with the IP
	RelationshipHistoricalSSLCertificates = "historical_ssl_certificates"

	// WHOIS information for the IP address
	RelationshipHistoricalWhois = "historical_whois"

	// Community posted comments in the IP's related objects
	RelationshipRelatedComments = "related_comments"

	// References related to the IP address (VT Enterprise only)
	RelationshipRelatedReferences = "related_references"

	// Threat actors related to the IP address (VT Enterprise only)
	RelationshipRelatedThreatActors = "related_threat_actors"

	// Files containing the IP address
	RelationshipReferrerFiles = "referrer_files"

	// IP address' resolutions
	RelationshipResolutions = "resolutions"

	// URLs related to the IP address (VT Enterprise only)
	RelationshipURLs = "urls"

	// Votes for the current user
	RelationshipUserVotes = "user_votes"

	// All votes on the IP address
	RelationshipVotes = "votes"
)
