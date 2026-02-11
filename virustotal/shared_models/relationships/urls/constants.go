package urls

// URL relationship constants from VirusTotal API documentation
// https://docs.virustotal.com/reference/url-object#relationships
const (
	// RelationshipAnalyses returns analyses for the URL (VT Enterprise only)
	// https://docs.virustotal.com/reference/url-object-analyses
	RelationshipAnalyses = "analyses"

	// RelationshipCollections returns collections containing the URL
	// https://docs.virustotal.com/reference/url-object-collections
	RelationshipCollections = "collections"

	// RelationshipComments returns community posted comments about the URL
	// https://docs.virustotal.com/reference/url-object-comments
	RelationshipComments = "comments"

	// RelationshipCommunicatingFiles returns files that communicate with the URL when executed (VT Enterprise only)
	// https://docs.virustotal.com/reference/url-object-communicating-files
	RelationshipCommunicatingFiles = "communicating_files"

	// RelationshipContactedDomains returns domains from which the URL loads resources (VT Enterprise only)
	// https://docs.virustotal.com/reference/url-object-contacted-domains
	RelationshipContactedDomains = "contacted_domains"

	// RelationshipContactedIPs returns IPs from which the URL loads resources (VT Enterprise only)
	// https://docs.virustotal.com/reference/url-object-contacted-ips
	RelationshipContactedIPs = "contacted_ips"

	// RelationshipDownloadedFiles returns files downloaded from the URL (VT Enterprise only)
	// https://docs.virustotal.com/reference/url-object-downloaded-files
	RelationshipDownloadedFiles = "downloaded_files"

	// RelationshipEmbeddedJSFiles returns JS scripts found in the URL's HTML response (VT Enterprise only)
	// https://docs.virustotal.com/reference/url-object-embedded-js-files
	RelationshipEmbeddedJSFiles = "embedded_js_files"

	// RelationshipGraphs returns graphs containing the URL
	// https://docs.virustotal.com/reference/url-object-graphs
	RelationshipGraphs = "graphs"

	// RelationshipLastServingIPAddress returns the last IP address that served the URL
	// https://docs.virustotal.com/reference/url-object-last-serving-ip-address
	RelationshipLastServingIPAddress = "last_serving_ip_address"

	// RelationshipNetworkLocation returns the domain or IP for the URL
	// https://docs.virustotal.com/reference/url-object-network-location
	RelationshipNetworkLocation = "network_location"

	// RelationshipRedirectingURLs returns URLs that redirected to the given URL (VT Enterprise only)
	// https://docs.virustotal.com/reference/url-object-redirecting-urls
	RelationshipRedirectingURLs = "redirecting_urls"

	// RelationshipRedirectsTo returns URLs that the URL redirects to (VT Enterprise only)
	// https://docs.virustotal.com/reference/url-object-redirects-to
	RelationshipRedirectsTo = "redirects_to"

	// RelationshipReferrerFiles returns files containing the URL (VT Enterprise only)
	// https://docs.virustotal.com/reference/url-object-referrer-files
	RelationshipReferrerFiles = "referrer_files"

	// RelationshipReferrerURLs returns URLs that refer to the given URL (VT Enterprise only)
	// https://docs.virustotal.com/reference/url-object-referrer-urls
	RelationshipReferrerURLs = "referrer_urls"

	// RelationshipRelatedComments returns community posted comments in the URL's related objects
	// https://docs.virustotal.com/reference/url-object-related-comments
	RelationshipRelatedComments = "related_comments"

	// RelationshipRelatedReferences returns references related to the URL (VT Enterprise only)
	// https://docs.virustotal.com/reference/url-object-related-references
	RelationshipRelatedReferences = "related_references"

	// RelationshipRelatedThreatActors returns threat actors related to the URL (VT Enterprise only)
	// https://docs.virustotal.com/reference/url-object-related-threat-actors
	RelationshipRelatedThreatActors = "related_threat_actors"

	// RelationshipSubmissions returns URL submissions (VT Enterprise only)
	// https://docs.virustotal.com/reference/url-object-submissions
	RelationshipSubmissions = "submissions"

	// RelationshipUserVotes returns votes for the URL made by the current user
	// https://docs.virustotal.com/reference/url-object-user-votes
	RelationshipUserVotes = "user_votes"

	// RelationshipVotes returns all votes for the URL
	// https://docs.virustotal.com/reference/url-object-votes
	RelationshipVotes = "votes"

	// RelationshipURLsRelatedByTrackerID returns URLs having trackers with the same IDs (VT Enterprise only)
	// https://docs.virustotal.com/reference/url-object-urls-related-by-tracker-id
	RelationshipURLsRelatedByTrackerID = "urls_related_by_tracker_id"
)
