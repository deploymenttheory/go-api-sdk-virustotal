package analyses

import (
	analyses_relationships "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models/relationships/analyses"
)

// API endpoints for analyses, submissions, and operations
const (
	EndpointAnalyses    = "/v3/analyses"
	EndpointSubmissions = "/v3/submissions"
	EndpointOperations  = "/v3/operations"
)

// Relationship names for analyses (from VT API documentation)
const (
	RelationshipItem = analyses_relationships.RelationshipItem
)
