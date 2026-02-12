package file_behaviours

import (
	file_behaviour_relationships "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models/relationships/file_behaviours"
)

// API endpoints for file behaviours
const (
	EndpointFiles          = "/files"
	EndpointFileBehaviours = "/file_behaviours"
)

// Relationship names for file behaviours (from VT API documentation)
// https://docs.virustotal.com/reference/file-behaviour-summary#relationships
const (
	// RelationshipFile returns the file for a given behaviour report
	// https://docs.virustotal.com/reference/file-behaviour-object-file
	RelationshipFile = file_behaviour_relationships.RelationshipFile

	// RelationshipAttackTechniques returns the attack techniques observed in the behaviour report
	// https://docs.virustotal.com/reference/file-behaviour-object-attack-techniques
	RelationshipAttackTechniques = file_behaviour_relationships.RelationshipAttackTechniques
)
