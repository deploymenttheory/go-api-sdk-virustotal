package attack_tactics

import (
	attack_tactics_relationships "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models/relationships/attack_tactics"
)

// Endpoint constants
const (
	// EndpointAttackTactics is the base endpoint for attack tactics operations
	EndpointAttackTactics = "/attack_tactics"
)

// Relationship constants for attack tactics
const (
	// RelationshipAttackTechniques represents the relationship to attack techniques
	RelationshipAttackTechniques = attack_tactics_relationships.RelationshipAttackTechniques
)
