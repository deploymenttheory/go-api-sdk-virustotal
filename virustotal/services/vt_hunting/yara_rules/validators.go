package yara_rules

import (
	"fmt"
)

// ValidateYaraRuleID validates a YARA rule ID
func ValidateYaraRuleID(ruleID string) error {
	if ruleID == "" {
		return fmt.Errorf("YARA rule ID cannot be empty")
	}
	return nil
}

// ValidateRelationship validates a relationship name
func ValidateRelationship(relationship string) error {
	if relationship == "" {
		return fmt.Errorf("relationship cannot be empty")
	}
	
	validRelationships := map[string]bool{
		RelationshipFiles: true,
	}
	
	if !validRelationships[relationship] {
		return fmt.Errorf("invalid relationship: %s (valid relationships: files)", relationship)
	}
	
	return nil
}
