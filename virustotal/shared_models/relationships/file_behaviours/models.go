package file_behaviours

import "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models"

// =============================================================================
// Relationship Response Types
// =============================================================================

// FileResponse represents the response for the file relationship
// Returns a single file object for the behaviour report
// https://docs.virustotal.com/reference/file-behaviour-object-file
type FileResponse struct {
	Data  shared_models.RelatedObject `json:"data"`
	Links shared_models.ObjectLinks   `json:"links"`
	Meta  shared_models.Meta          `json:"meta"`
}

// AttackTechniquesResponse represents the response for the attack_techniques relationship
// Returns a list of attack technique objects observed in the behaviour report
// https://docs.virustotal.com/reference/file-behaviour-object-attack-techniques
type AttackTechniquesResponse = shared_models.RelatedObjectsResponse

// =============================================================================
// Context Attributes for File Behaviour Relationships
// =============================================================================

// AttackTechniqueContextAttributes represents the context attributes for attack techniques
// Contains signatures (behaviours) observed where this technique applies
type AttackTechniqueContextAttributes struct {
	Signatures []AttackTechniqueSignature `json:"signatures"`
}

// AttackTechniqueSignature represents a signature (behaviour) for an attack technique
type AttackTechniqueSignature struct {
	Description string `json:"description"` // Description of the behaviour
	Severity    string `json:"severity"`    // Severity of the behaviour (UNKNOWN, INFO, LOW, MEDIUM, HIGH)
}
