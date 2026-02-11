package analyses

import "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models"

// =============================================================================
// Generic Relationship Response Types (Type Aliases)
// =============================================================================

// ItemResponse represents the response for the item relationship
// Returns the file or URL that was analyzed
// https://docs.virustotal.com/reference/analysis-object-item
type ItemResponse = shared_models.RelatedObjectsResponse
