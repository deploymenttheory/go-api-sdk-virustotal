package file_behaviours

// File behaviour relationship constants from VirusTotal API documentation
// https://docs.virustotal.com/reference/file-behaviour-summary#relationships
const (
	// RelationshipFile returns the file for a given behaviour report
	// https://docs.virustotal.com/reference/file-behaviour-object-file
	RelationshipFile = "file"

	// RelationshipAttackTechniques returns the attack techniques observed in the behaviour report
	// https://docs.virustotal.com/reference/file-behaviour-object-attack-techniques
	RelationshipAttackTechniques = "attack_techniques"
)
