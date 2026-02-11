package domains

import (
	domain_relationships "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models/relationships/domains"
)

// API endpoints for domains
const (
	EndpointDomains = "/domains"
)

// Relationship names for domains (from VT API documentation)
const (
	RelationshipCAARecords                = domain_relationships.RelationshipCAARecords
	RelationshipCNAMERecords              = domain_relationships.RelationshipCNAMERecords
	RelationshipCollections               = domain_relationships.RelationshipCollections
	RelationshipComments                  = domain_relationships.RelationshipComments
	RelationshipCommunicatingFiles        = domain_relationships.RelationshipCommunicatingFiles
	RelationshipDownloadedFiles           = domain_relationships.RelationshipDownloadedFiles
	RelationshipGraphs                    = domain_relationships.RelationshipGraphs
	RelationshipHistoricalSSLCertificates = domain_relationships.RelationshipHistoricalSSLCertificates
	RelationshipHistoricalWhois           = domain_relationships.RelationshipHistoricalWhois
	RelationshipImmediateParent           = domain_relationships.RelationshipImmediateParent
	RelationshipMXRecords                 = domain_relationships.RelationshipMXRecords
	RelationshipNSRecords                 = domain_relationships.RelationshipNSRecords
	RelationshipParent                    = domain_relationships.RelationshipParent
	RelationshipReferrerFiles             = domain_relationships.RelationshipReferrerFiles
	RelationshipRelatedComments           = domain_relationships.RelationshipRelatedComments
	RelationshipRelatedReferences         = domain_relationships.RelationshipRelatedReferences
	RelationshipRelatedThreatActors       = domain_relationships.RelationshipRelatedThreatActors
	RelationshipResolutions               = domain_relationships.RelationshipResolutions
	RelationshipSiblings                  = domain_relationships.RelationshipSiblings
	RelationshipSOARecords                = domain_relationships.RelationshipSOARecords
	RelationshipSubdomains                = domain_relationships.RelationshipSubdomains
	RelationshipURLs                      = domain_relationships.RelationshipURLs
	RelationshipUserVotes                 = domain_relationships.RelationshipUserVotes
	RelationshipVotes                     = domain_relationships.RelationshipVotes
)
