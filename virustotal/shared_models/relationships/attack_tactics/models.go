package attack_tactics

import "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models"

// =============================================================================
// Generic Relationship Response Types (Type Aliases)
// =============================================================================

// AttackTechniquesResponse represents the response for the attack_techniques relationship
// https://docs.virustotal.com/reference/attack-tactic-object-attack-techniques
type AttackTechniquesResponse = shared_models.RelatedObjectsResponse
