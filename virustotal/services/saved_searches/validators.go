package saved_searches

import (
	"fmt"
	"regexp"
	"slices"
)

// Saved search ID pattern - alphanumeric hexadecimal string
var savedSearchIDPattern = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

// ValidateSavedSearchID validates a saved search identifier
//
// Saved search IDs are 32-character hexadecimal strings
//
// Returns an error if the identifier is invalid
func ValidateSavedSearchID(searchID string) error {
	if searchID == "" {
		return fmt.Errorf("saved search ID cannot be empty")
	}

	if !savedSearchIDPattern.MatchString(searchID) {
		return fmt.Errorf("saved search ID must be a 32-character hexadecimal string")
	}

	return nil
}

// ValidateAccessType validates an access type
//
// Valid access types:
//  - "viewers" for view access
//  - "editors" for edit access
//
// Returns an error if the access type is invalid
func ValidateAccessType(accessType string) error {
	if accessType == "" {
		return fmt.Errorf("access type cannot be empty")
	}

	validTypes := []string{AccessTypeViewers, AccessTypeEditors}

	if !slices.Contains(validTypes, accessType) {
		return fmt.Errorf("access type must be one of: viewers, editors")
	}

	return nil
}

// ValidateObjectType validates an object type for access control
//
// Valid object types:
//  - "user" for user entities
//  - "group" for group entities
//
// Returns an error if the object type is invalid
func ValidateObjectType(objectType string) error {
	if objectType == "" {
		return fmt.Errorf("object type cannot be empty")
	}

	validTypes := []string{ObjectTypeUser, ObjectTypeGroup}

	if !slices.Contains(validTypes, objectType) {
		return fmt.Errorf("object type must be one of: user, group")
	}

	return nil
}
