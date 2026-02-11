package saved_searches

// SavedSearchAttributes represents the attributes of a saved search
type SavedSearchAttributes struct {
	Name            string   `json:"name"`
	Description     string   `json:"description,omitempty"`
	SearchQuery     string   `json:"search_query"`
	Private         bool     `json:"private"`
	Tags            []string `json:"tags,omitempty"`
	CreationDate    int64    `json:"creation_date,omitempty"`
	ModificationDate int64   `json:"last_modification_date,omitempty"`
	Origin          string   `json:"origin,omitempty"`
}

// SavedSearchLinks represents links associated with a saved search
type SavedSearchLinks struct {
	Self string `json:"self"`
}

// SavedSearchData represents the main saved search data
type SavedSearchData struct {
	Attributes SavedSearchAttributes `json:"attributes"`
	ID         string                `json:"id,omitempty"`
	Links      SavedSearchLinks      `json:"links,omitempty"`
	Type       string                `json:"type"`
}

// Meta represents pagination metadata
type Meta struct {
	Cursor string `json:"cursor,omitempty"`
	Count  int    `json:"count,omitempty"`
}

// Links represents pagination links
type Links struct {
	Self string `json:"self"`
	Next string `json:"next,omitempty"`
}

// =============================================================================
// List Saved Searches Response
// =============================================================================

// ListSavedSearchesResponse represents the response from listing saved searches
type ListSavedSearchesResponse struct {
	Data  []SavedSearchData `json:"data"`
	Links Links             `json:"links"`
	Meta  Meta              `json:"meta,omitempty"`
}

// =============================================================================
// Get Saved Search Response
// =============================================================================

// GetSavedSearchResponse represents the response from getting a single saved search
type GetSavedSearchResponse struct {
	Data SavedSearchData `json:"data"`
}

// =============================================================================
// Create Saved Search Request/Response
// =============================================================================

// CreateSavedSearchRequest represents the request body for creating a saved search
type CreateSavedSearchRequest struct {
	Data SavedSearchData `json:"data"`
}

// CreateSavedSearchResponse represents the response from creating a saved search
type CreateSavedSearchResponse struct {
	Data SavedSearchData `json:"data"`
}

// =============================================================================
// Update Saved Search Request/Response
// =============================================================================

// UpdateSavedSearchRequest represents the request body for updating a saved search
type UpdateSavedSearchRequest struct {
	Data SavedSearchData `json:"data"`
}

// UpdateSavedSearchResponse represents the response from updating a saved search
type UpdateSavedSearchResponse struct {
	Data SavedSearchData `json:"data"`
}

// =============================================================================
// Share/Revoke Access Request
// =============================================================================

// AccessEntity represents a user or group for access control
type AccessEntity struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// ShareAccessRequest represents the request body for sharing or revoking access
type ShareAccessRequest struct {
	Data []AccessEntity `json:"data"`
}

// =============================================================================
// Related Objects Response
// =============================================================================

// RelatedObjectAttributes represents attributes of objects related to a saved search
type RelatedObjectAttributes struct {
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Email       string `json:"email,omitempty"`
}

// RelatedObject represents an object related to a saved search
type RelatedObject struct {
	Attributes RelatedObjectAttributes `json:"attributes"`
	ID         string                  `json:"id"`
	Links      SavedSearchLinks        `json:"links,omitempty"`
	Type       string                  `json:"type"`
}

// RelatedObjectsResponse represents the response from getting objects related to a saved search
type RelatedObjectsResponse struct {
	Data  []RelatedObject `json:"data"`
	Links Links           `json:"links"`
	Meta  Meta            `json:"meta,omitempty"`
}

// =============================================================================
// Object Descriptors Response
// =============================================================================

// ObjectDescriptor represents a lightweight object descriptor
type ObjectDescriptor struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// ObjectDescriptorsResponse represents the response from getting object descriptors
type ObjectDescriptorsResponse struct {
	Data  []ObjectDescriptor `json:"data"`
	Links Links              `json:"links"`
	Meta  Meta               `json:"meta,omitempty"`
}

// =============================================================================
// Query Options
// =============================================================================

// ListSavedSearchesOptions represents optional parameters for listing saved searches
type ListSavedSearchesOptions struct {
	Filter       string // Filter expression (e.g., "creation_date:2025-10-27+")
	Order        string // Ordering expression (e.g., "last_modification_date-")
	Limit        int    // Maximum number of searches to retrieve
	Cursor       string // Pagination cursor
	Relationships string // Comma-separated relationships to include
	Attributes   string // Comma-separated attributes to include
}

// GetSavedSearchOptions represents optional parameters for getting a saved search
type GetSavedSearchOptions struct {
	Relationships string // Comma-separated relationships to include
	Attributes   string // Comma-separated attributes to include
}

// GetRelatedObjectsOptions represents optional parameters for getting related objects
type GetRelatedObjectsOptions struct {
	Limit  int    // Maximum number of objects to retrieve
	Cursor string // Pagination cursor
}
