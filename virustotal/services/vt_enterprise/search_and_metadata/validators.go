package search_and_metadata

import (
	"fmt"
)

// ValidateSearchQuery validates a search query string
// Query cannot be empty
func ValidateSearchQuery(query string) error {
	if query == "" {
		return fmt.Errorf("search query cannot be empty")
	}
	return nil
}

// ValidateSnippetID validates a snippet ID
// Snippet ID cannot be empty
func ValidateSnippetID(snippetID string) error {
	if snippetID == "" {
		return fmt.Errorf("snippet ID cannot be empty")
	}
	return nil
}
