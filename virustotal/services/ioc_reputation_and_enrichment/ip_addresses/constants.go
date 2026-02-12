package ipaddresses

import (
	ip_relationships "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models/relationships/ip_addresses"
)

// API endpoints for IP addresses
const (
	EndpointIPAddresses = "/ip_addresses"
)

// Relationship names for IP addresses (from VT API documentation)
const (
	RelationshipCollections               = ip_relationships.RelationshipCollections
	RelationshipComments                  = ip_relationships.RelationshipComments
	RelationshipCommunicatingFiles        = ip_relationships.RelationshipCommunicatingFiles
	RelationshipDownloadedFiles           = ip_relationships.RelationshipDownloadedFiles
	RelationshipGraphs                    = ip_relationships.RelationshipGraphs
	RelationshipHistoricalSSLCertificates = ip_relationships.RelationshipHistoricalSSLCertificates
	RelationshipHistoricalWhois           = ip_relationships.RelationshipHistoricalWhois
	RelationshipRelatedComments           = ip_relationships.RelationshipRelatedComments
	RelationshipRelatedReferences         = ip_relationships.RelationshipRelatedReferences
	RelationshipRelatedThreatActors       = ip_relationships.RelationshipRelatedThreatActors
	RelationshipReferrerFiles             = ip_relationships.RelationshipReferrerFiles
	RelationshipResolutions               = ip_relationships.RelationshipResolutions
	RelationshipURLs                      = ip_relationships.RelationshipURLs
	RelationshipUserVotes                 = ip_relationships.RelationshipUserVotes
	RelationshipVotes                     = ip_relationships.RelationshipVotes
)
