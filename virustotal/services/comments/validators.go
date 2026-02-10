package comments

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Comment ID pattern based on VirusTotal API documentation
// https://docs.virustotal.com/reference/comments-api
// Format: {prefix}-{item_id}-{random}
// Prefix can be: d (domain), f (file), g (graph), i (IP), u (URL)
var commentIDPattern = regexp.MustCompile(`^[dfgiu]-.+-.+$`)

// ValidateCommentID validates a comment identifier
//
// Comment IDs have three main parts divided by a '-' character:
//  1. A character representing the item where the comment is posted:
//     - 'd' if the comment is posted in a domain
//     - 'f' if the comment is posted in a file
//     - 'g' if the comment is posted in a graph
//     - 'i' if the comment is posted in an IP address
//     - 'u' if the comment is posted in a URL
//  2. The item's ID
//  3. A random string
//
// Returns an error if the identifier is invalid
func ValidateCommentID(commentID string) error {
	if commentID == "" {
		return fmt.Errorf("comment ID cannot be empty")
	}

	// Check basic pattern first
	if !commentIDPattern.MatchString(commentID) {
		return fmt.Errorf("comment ID must be in format {prefix}-{item_id}-{random}, where prefix is d/f/g/i/u")
	}

	// Split and validate parts count
	parts := strings.Split(commentID, "-")
	if len(parts) < 3 {
		return fmt.Errorf("comment ID must have at least 3 parts separated by '-'")
	}

	// Validate prefix (this will only be reached if pattern matched, so prefix exists)
	prefix := parts[0]
	validPrefixes := []string{"d", "f", "g", "i", "u"}

	if !slices.Contains(validPrefixes, prefix) {
		return fmt.Errorf("comment ID prefix must be one of: d (domain), f (file), g (graph), i (IP), u (URL)")
	}

	return nil
}
