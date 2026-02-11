package shared_models

// Meta represents pagination metadata common to all VirusTotal API responses
type Meta struct {
	Cursor string `json:"cursor,omitempty"` // Pagination cursor
	Count  int    `json:"count,omitempty"`  // Total count
}

// Links represents pagination links common to all VirusTotal API responses
type Links struct {
	Self string `json:"self"`           // Self link
	Next string `json:"next,omitempty"` // Next page link
}

// ObjectLinks represents basic object links
type ObjectLinks struct {
	Self string `json:"self"` // URL to this object
}

// RelationshipError represents an error for a related object not found in the database
type RelationshipError struct {
	Code    string `json:"code"`    // Error code (e.g., "NotFoundError")
	Message string `json:"message"` // Error message
}

// ObjectDescriptor represents a lightweight descriptor of a related object
type ObjectDescriptor struct {
	Type              string         `json:"type"`                         // Object type
	ID                string         `json:"id"`                           // Object ID
	ContextAttributes map[string]any `json:"context_attributes,omitempty"` // Context-specific attributes
	Error             *RelationshipError `json:"error,omitempty"`          // Error if object not found
}

// RelatedObject represents a full object related to a primary object
type RelatedObject struct {
	Type              string             `json:"type"`                         // Object type
	ID                string             `json:"id"`                           // Object ID
	Links             *ObjectLinks       `json:"links,omitempty"`              // Object links
	Attributes        map[string]any     `json:"attributes,omitempty"`         // Object attributes (varies by type)
	ContextAttributes map[string]any     `json:"context_attributes,omitempty"` // Context-specific attributes
	Error             *RelationshipError `json:"error,omitempty"`              // Error if object not found
}

// RelatedObjectsResponse represents the response from getting related objects
type RelatedObjectsResponse struct {
	Data  []RelatedObject `json:"data"`            // Array of related objects
	Links Links           `json:"links,omitempty"` // Pagination links
	Meta  *Meta           `json:"meta,omitempty"`  // Metadata including cursor
}

// ObjectDescriptorsResponse represents the response from getting object descriptors
type ObjectDescriptorsResponse struct {
	Data  []ObjectDescriptor `json:"data"`            // Array of object descriptors
	Links Links              `json:"links,omitempty"` // Pagination links
	Meta  *Meta              `json:"meta,omitempty"`  // Metadata including cursor
}

// RelatedObjectsOptions contains optional parameters for relationship requests
type RelatedObjectsOptions struct {
	Limit  int    // Maximum number of objects to return per page
	Cursor string // Pagination cursor - if provided, returns single page only
}
