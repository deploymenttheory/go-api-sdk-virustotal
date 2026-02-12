package files

import (
	file_relationships "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models/relationships/files"
)

// API endpoints for files
const (
	EndpointFiles        = "/files"
	EndpointSigmaRules   = "/sigma_rules"
	EndpointYARARulesets = "/yara_rulesets"
)

// Relationship names for files (from VT API documentation)
// https://docs.virustotal.com/reference/files#relationships
const (
	RelationshipAnalyses             = file_relationships.RelationshipAnalyses
	RelationshipBehaviours           = file_relationships.RelationshipBehaviours
	RelationshipBundledFiles         = file_relationships.RelationshipBundledFiles
	RelationshipCarbonBlackChildren  = file_relationships.RelationshipCarbonBlackChildren
	RelationshipCarbonBlackParents   = file_relationships.RelationshipCarbonBlackParents
	RelationshipCollections          = file_relationships.RelationshipCollections
	RelationshipComments             = file_relationships.RelationshipComments
	RelationshipCompressedParents    = file_relationships.RelationshipCompressedParents
	RelationshipContactedDomains     = file_relationships.RelationshipContactedDomains
	RelationshipContactedIPs         = file_relationships.RelationshipContactedIPs
	RelationshipContactedURLs        = file_relationships.RelationshipContactedURLs
	RelationshipDroppedFiles         = file_relationships.RelationshipDroppedFiles
	RelationshipEmailAttachments     = file_relationships.RelationshipEmailAttachments
	RelationshipEmailParents         = file_relationships.RelationshipEmailParents
	RelationshipEmbeddedDomains      = file_relationships.RelationshipEmbeddedDomains
	RelationshipEmbeddedIPs          = file_relationships.RelationshipEmbeddedIPs
	RelationshipEmbeddedURLs         = file_relationships.RelationshipEmbeddedURLs
	RelationshipExecutionParents     = file_relationships.RelationshipExecutionParents
	RelationshipGraphs               = file_relationships.RelationshipGraphs
	RelationshipITWDomains           = file_relationships.RelationshipITWDomains
	RelationshipITWIPs               = file_relationships.RelationshipITWIPs
	RelationshipITWURLs              = file_relationships.RelationshipITWURLs
	RelationshipMemoryPatternDomains = file_relationships.RelationshipMemoryPatternDomains
	RelationshipMemoryPatternIPs     = file_relationships.RelationshipMemoryPatternIPs
	RelationshipMemoryPatternURLs    = file_relationships.RelationshipMemoryPatternURLs
	RelationshipOverlayChildren      = file_relationships.RelationshipOverlayChildren
	RelationshipOverlayParents       = file_relationships.RelationshipOverlayParents
	RelationshipPCAPChildren         = file_relationships.RelationshipPCAPChildren
	RelationshipPCAPParents          = file_relationships.RelationshipPCAPParents
	RelationshipPEResourceChildren   = file_relationships.RelationshipPEResourceChildren
	RelationshipPEResourceParents    = file_relationships.RelationshipPEResourceParents
	RelationshipRelatedReferences    = file_relationships.RelationshipRelatedReferences
	RelationshipRelatedThreatActors  = file_relationships.RelationshipRelatedThreatActors
	RelationshipScreenshots          = file_relationships.RelationshipScreenshots
	RelationshipSigmaAnalysis        = file_relationships.RelationshipSigmaAnalysis
	RelationshipSimilarFiles         = file_relationships.RelationshipSimilarFiles
	RelationshipSubmissions          = file_relationships.RelationshipSubmissions
	RelationshipURLsForEmbeddedJS    = file_relationships.RelationshipURLsForEmbeddedJS
	RelationshipUserVotes            = file_relationships.RelationshipUserVotes
	RelationshipVotes                = file_relationships.RelationshipVotes
)
