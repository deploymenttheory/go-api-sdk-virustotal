package files

// File relationship constants from VirusTotal API documentation
// https://docs.virustotal.com/reference/files#relationships
const (
	// RelationshipAnalyses returns analyses for the file (VT Enterprise only)
	RelationshipAnalyses = "analyses"

	// RelationshipBehaviours returns behaviour reports for the file
	RelationshipBehaviours = "behaviours"

	// RelationshipBundledFiles returns files bundled within the file
	RelationshipBundledFiles = "bundled_files"

	// RelationshipCarbonBlackChildren returns files derived from the file according to Carbon Black (VT Enterprise only)
	RelationshipCarbonBlackChildren = "carbonblack_children"

	// RelationshipCarbonBlackParents returns files from where the file was derived according to Carbon Black (VT Enterprise only)
	RelationshipCarbonBlackParents = "carbonblack_parents"

	// RelationshipCollections returns collections where the file is present
	RelationshipCollections = "collections"

	// RelationshipComments returns comments for the file
	RelationshipComments = "comments"

	// RelationshipCompressedParents returns compressed files that contain the file (VT Enterprise only)
	RelationshipCompressedParents = "compressed_parents"

	// RelationshipContactedDomains returns domains contacted by the file
	RelationshipContactedDomains = "contacted_domains"

	// RelationshipContactedIPs returns IP addresses contacted by the file
	RelationshipContactedIPs = "contacted_ips"

	// RelationshipContactedURLs returns URLs contacted by the file
	RelationshipContactedURLs = "contacted_urls"

	// RelationshipDroppedFiles returns files dropped by the file during its execution
	RelationshipDroppedFiles = "dropped_files"

	// RelationshipEmailAttachments returns files attached to the email (VT Enterprise only)
	RelationshipEmailAttachments = "email_attachments"

	// RelationshipEmailParents returns email files that contained the file (VT Enterprise only)
	RelationshipEmailParents = "email_parents"

	// RelationshipEmbeddedDomains returns domain names embedded in the file (VT Enterprise only)
	RelationshipEmbeddedDomains = "embedded_domains"

	// RelationshipEmbeddedIPs returns IP addresses embedded in the file (VT Enterprise only)
	RelationshipEmbeddedIPs = "embedded_ips"

	// RelationshipEmbeddedURLs returns URLs embedded in the file (VT Enterprise only)
	RelationshipEmbeddedURLs = "embedded_urls"

	// RelationshipExecutionParents returns files that executed the file
	RelationshipExecutionParents = "execution_parents"

	// RelationshipGraphs returns graphs that include the file
	RelationshipGraphs = "graphs"

	// RelationshipITWDomains returns in the wild domain names from where the file has been downloaded (VT Enterprise only)
	RelationshipITWDomains = "itw_domains"

	// RelationshipITWIPs returns in the wild IP addresses from where the file has been downloaded (VT Enterprise only)
	RelationshipITWIPs = "itw_ips"

	// RelationshipITWURLs returns in the wild URLs from where the file has been downloaded (VT Enterprise only)
	RelationshipITWURLs = "itw_urls"

	// RelationshipMemoryPatternDomains returns domain names in the memory pattern of the file (VT Enterprise only)
	RelationshipMemoryPatternDomains = "memory_pattern_domains"

	// RelationshipMemoryPatternIPs returns IP addresses in the memory pattern of the file (VT Enterprise only)
	RelationshipMemoryPatternIPs = "memory_pattern_ips"

	// RelationshipMemoryPatternURLs returns URLs in the memory pattern of the file (VT Enterprise only)
	RelationshipMemoryPatternURLs = "memory_pattern_urls"

	// RelationshipOverlayChildren returns files contained by the file as an overlay (VT Enterprise only)
	RelationshipOverlayChildren = "overlay_children"

	// RelationshipOverlayParents returns files that contain the file as an overlay (VT Enterprise only)
	RelationshipOverlayParents = "overlay_parents"

	// RelationshipPCAPChildren returns files contained within the PCAP file (VT Enterprise only)
	RelationshipPCAPChildren = "pcap_children"

	// RelationshipPCAPParents returns PCAP files that contain the file (VT Enterprise only)
	RelationshipPCAPParents = "pcap_parents"

	// RelationshipPEResourceChildren returns files contained by a PE file as a resource
	RelationshipPEResourceChildren = "pe_resource_children"

	// RelationshipPEResourceParents returns PE files containing the file as a resource
	RelationshipPEResourceParents = "pe_resource_parents"

	// RelationshipRelatedReferences returns references related to the file (VT Enterprise only, requires Threat Landscape)
	RelationshipRelatedReferences = "related_references"

	// RelationshipRelatedThreatActors returns threat actors related to the file (VT Enterprise only, requires Threat Landscape)
	RelationshipRelatedThreatActors = "related_threat_actors"

	// RelationshipScreenshots returns screenshots related to the sandbox execution of the file (VT Enterprise only)
	RelationshipScreenshots = "screenshots"

	// RelationshipSigmaAnalysis returns sigma analysis for the file
	RelationshipSigmaAnalysis = "sigma_analysis"

	// RelationshipSimilarFiles returns files that are similar to the file (VT Enterprise only)
	RelationshipSimilarFiles = "similar_files"

	// RelationshipSubmissions returns submissions for the file (VT Enterprise only)
	RelationshipSubmissions = "submissions"

	// RelationshipURLsForEmbeddedJS returns URLs where a given JS script is embedded (VT Enterprise only)
	RelationshipURLsForEmbeddedJS = "urls_for_embedded_js"

	// RelationshipUserVotes returns current user's votes
	RelationshipUserVotes = "user_votes"

	// RelationshipVotes returns all votes on the file
	RelationshipVotes = "votes"
)
