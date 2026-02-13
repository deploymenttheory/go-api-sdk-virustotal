package search_and_metadata

import (
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models"
)

// =============================================================================
// Common Structures
// =============================================================================

type Links = shared_models.Links
type Meta = shared_models.Meta

// =============================================================================
// Search Options
// =============================================================================

// SearchOptions contains options for basic search queries
type SearchOptions struct {
	Limit  int    `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}

// IntelligenceSearchOptions contains options for intelligence search queries
type IntelligenceSearchOptions struct {
	Limit           int    `json:"limit,omitempty"`
	Cursor          string `json:"cursor,omitempty"`
	Order           string `json:"order,omitempty"`
	DescriptorsOnly bool   `json:"descriptors_only,omitempty"`
}

// =============================================================================
// Basic Search Models
// =============================================================================

// SearchResponse represents the response from a basic search query
// Returns files, URLs, domains, IP addresses, or comments matching the query
type SearchResponse struct {
	Data  []SearchResult `json:"data"`
	Links Links          `json:"links,omitempty"`
	Meta  Meta           `json:"meta,omitempty"`
}

// SearchResult represents a single search result
// The actual structure varies based on entity type (file, url, domain, ip_address, comment)
type SearchResult struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Links      Links          `json:"links,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// =============================================================================
// Intelligence Search Models (VT Enterprise)
// =============================================================================

// IntelligenceSearchResponse represents the response from an intelligence search query
type IntelligenceSearchResponse struct {
	Data  []IntelligenceSearchResult `json:"data"`
	Links Links                      `json:"links,omitempty"`
	Meta  IntelligenceSearchMeta     `json:"meta,omitempty"`
}

// IntelligenceSearchResult represents a single intelligence search result
// Can include context_attributes for content searches or similarity searches
type IntelligenceSearchResult struct {
	Type              string                         `json:"type"`
	ID                string                         `json:"id"`
	Links             Links                          `json:"links,omitempty"`
	Attributes        map[string]any                 `json:"attributes,omitempty"`
	ContextAttributes *IntelligenceContextAttributes `json:"context_attributes,omitempty"`
}

// IntelligenceContextAttributes contains additional context for certain search types
type IntelligenceContextAttributes struct {
	// Content search attributes
	Confidence     *float64 `json:"confidence,omitempty"`
	MatchInSubfile *bool    `json:"match_in_subfile,omitempty"`
	Snippet        string   `json:"snippet,omitempty"`

	// Similarity search attributes
	SimilarityScore *float64 `json:"similarity_score,omitempty"`
}

// IntelligenceSearchMeta contains metadata for intelligence search results
type IntelligenceSearchMeta struct {
	Cursor   string `json:"cursor,omitempty"`
	DaysBack int    `json:"days_back,omitempty"`
}

// =============================================================================
// Search Snippets Models (VT Enterprise)
// =============================================================================

// SnippetsResponse represents the response for file content search snippets
// Returns a list of strings containing hexdump and plain text
// Matched content is found between '*' characters
type SnippetsResponse struct {
	Data []string `json:"data"`
}

// =============================================================================
// Metadata Models (VT Enterprise)
// =============================================================================

// MetadataResponse represents VirusTotal metadata including engines and privileges
type MetadataResponse struct {
	Data MetadataData `json:"data"`
}

// MetadataData contains engines, privileges, and relationships metadata
type MetadataData struct {
	Engines       map[string]any                    `json:"engines,omitempty"`
	Privileges    []string                          `json:"privileges,omitempty"`
	Relationships map[string][]RelationshipMetadata `json:"relationships,omitempty"`
}

// RelationshipMetadata describes a relationship available in the API
type RelationshipMetadata struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}
