package attack_techniques

import (
	attack_techniques_relationships "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models/relationships/attack_techniques"
)

// Endpoint constants
const (
	// EndpointAttackTechniques is the base endpoint for attack techniques operations
	EndpointAttackTechniques = "/attack_techniques"
)

// Relationship constants for attack techniques
const (
	// RelationshipAttackTactics returns the list of all attack tactics where the technique appears
	RelationshipAttackTactics = attack_techniques_relationships.RelationshipAttackTactics

	// RelationshipParentTechnique returns the technique's parent technique
	RelationshipParentTechnique = attack_techniques_relationships.RelationshipParentTechnique

	// RelationshipRevokingTechnique returns the attack technique revoking a technique
	RelationshipRevokingTechnique = attack_techniques_relationships.RelationshipRevokingTechnique

	// RelationshipSubtechniques returns the list of sub-techniques of the technique
	RelationshipSubtechniques = attack_techniques_relationships.RelationshipSubtechniques

	// RelationshipThreatActors returns the list of all threat actors where this technique appears
	RelationshipThreatActors = attack_techniques_relationships.RelationshipThreatActors
)
