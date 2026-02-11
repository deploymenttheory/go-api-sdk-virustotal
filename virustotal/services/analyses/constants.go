package analyses

// API endpoints for analyses, submissions, and operations
const (
	EndpointAnalyses    = "/analyses"
	EndpointSubmissions = "/submissions"
	EndpointOperations  = "/operations"
)

// Relationship names for analyses (from VT API documentation)
const (
	RelationshipItem = "item" // Returns the file or URL object that was analyzed
)
