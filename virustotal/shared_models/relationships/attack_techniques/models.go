package attack_techniques

import "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models"

// =============================================================================
// Generic Relationship Response Types (Type Aliases)
// =============================================================================

// AttackTacticsResponse represents the response for the attack_tactics relationship
// https://docs.virustotal.com/reference/attack-technique-object-attack-tactics
type AttackTacticsResponse = shared_models.RelatedObjectsResponse

// SubtechniquesResponse represents the response for the subtechniques relationship
// https://docs.virustotal.com/reference/attack-technique-object-subtechniques
type SubtechniquesResponse = shared_models.RelatedObjectsResponse

// ThreatActorsResponse represents the response for the threat_actors relationship
// https://docs.virustotal.com/reference/attack-technique-object-threat-actors
type ThreatActorsResponse = shared_models.RelatedObjectsResponse

// =============================================================================
// Single Object Relationship Response Types
// =============================================================================

// ParentTechniqueResponse represents the response for the parent_technique relationship
// Returns a single attack technique object (or none if the technique is not a sub-technique)
// https://docs.virustotal.com/reference/attack-technique-object-parent-technique
type ParentTechniqueResponse = shared_models.RelatedObjectsResponse

// RevokingTechniqueResponse represents the response for the revoking_technique relationship
// Returns a single attack technique object (or none if the technique is not revoked)
// https://docs.virustotal.com/reference/attack-technique-object-revoking-technique
type RevokingTechniqueResponse = shared_models.RelatedObjectsResponse
