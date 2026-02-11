package attack_techniques

// Attack Techniques relationship constants from VirusTotal API documentation
// https://docs.virustotal.com/reference/attack-techniques#relationships
const (
	// RelationshipAttackTactics returns the list of all attack tactics where the technique appears
	// https://docs.virustotal.com/reference/attack-technique-object-attack-tactics
	RelationshipAttackTactics = "attack_tactics"

	// RelationshipParentTechnique returns the technique's parent technique (single object)
	// https://docs.virustotal.com/reference/attack-technique-object-parent-technique
	RelationshipParentTechnique = "parent_technique"

	// RelationshipRevokingTechnique returns the attack technique revoking a technique (single object)
	// https://docs.virustotal.com/reference/attack-technique-object-revoking-technique
	RelationshipRevokingTechnique = "revoking_technique"

	// RelationshipSubtechniques returns the list of sub-techniques of the technique
	// https://docs.virustotal.com/reference/attack-technique-object-subtechniques
	RelationshipSubtechniques = "subtechniques"

	// RelationshipThreatActors returns the list of all threat actors where this technique appears (premium)
	// https://docs.virustotal.com/reference/attack-technique-object-threat-actors
	RelationshipThreatActors = "threat_actors"
)
