package client

import (
	"fmt"
	"strings"
)

// RelationshipEndpointType defines the type of relationship endpoint to use
type RelationshipEndpointType int

const (
	// RelationshipTypeFull returns full objects with all attributes
	// URL pattern: /{collection}/{id}/{relationship}
	RelationshipTypeFull RelationshipEndpointType = iota

	// RelationshipTypeDescriptor returns only object type and ID (more efficient)
	// URL pattern: /{collection}/{id}/relationships/{relationship}
	RelationshipTypeDescriptor
)

// RelationshipBuilder provides utilities for constructing relationship URLs and query parameters
// based on the VirusTotal API v3 relationships specification.
//
// VirusTotal API docs: https://docs.virustotal.com/reference/relationships
type RelationshipBuilder struct {
	baseEndpoint   string // Base endpoint path from constants (e.g., "/files", "/domains")
	id             string
	relationships  []string
	endpointType   RelationshipEndpointType
	includeInQuery bool
}

// NewRelationshipBuilder creates a new relationship builder for a given endpoint and resource ID
//
// Parameters:
//   - baseEndpoint: The API endpoint constant (e.g., EndpointFiles, EndpointDomains)
//   - id: The resource identifier
//
// Example:
//
//	rb := client.NewRelationshipBuilder(files.EndpointFiles, "44d88612fea8a8f36de82e1278abb02f")
func NewRelationshipBuilder(baseEndpoint, id string) *RelationshipBuilder {
	return &RelationshipBuilder{
		baseEndpoint:   baseEndpoint,
		id:             id,
		relationships:  make([]string, 0),
		endpointType:   RelationshipTypeFull,
		includeInQuery: false,
	}
}

// WithRelationship adds a relationship to be included
//
// Example:
//
//	rb.WithRelationship("comments").WithRelationship("votes")
func (rb *RelationshipBuilder) WithRelationship(relationship string) *RelationshipBuilder {
	if relationship != "" {
		rb.relationships = append(rb.relationships, relationship)
	}
	return rb
}

// WithRelationships adds multiple relationships to be included
//
// Example:
//
//	rb.WithRelationships("comments", "votes", "analyses")
func (rb *RelationshipBuilder) WithRelationships(relationships ...string) *RelationshipBuilder {
	for _, rel := range relationships {
		if rel != "" {
			rb.relationships = append(rb.relationships, rel)
		}
	}
	return rb
}

// AsDescriptorsOnly sets the endpoint type to return only descriptors (type and ID)
// This is more efficient when you only need identifiers.
//
// URL pattern: /{collection}/{id}/relationships/{relationship}
func (rb *RelationshipBuilder) AsDescriptorsOnly() *RelationshipBuilder {
	rb.endpointType = RelationshipTypeDescriptor
	return rb
}

// AsFullObjects sets the endpoint type to return full objects with all attributes
//
// URL pattern: /{collection}/{id}/{relationship}
func (rb *RelationshipBuilder) AsFullObjects() *RelationshipBuilder {
	rb.endpointType = RelationshipTypeFull
	return rb
}

// AsQueryParameter sets whether to include relationships as a query parameter
// instead of building a relationship endpoint URL.
//
// When enabled, builds: /{collection}/{id}?relationships={rel1},{rel2}
// When disabled, builds relationship-specific endpoints
func (rb *RelationshipBuilder) AsQueryParameter() *RelationshipBuilder {
	rb.includeInQuery = true
	return rb
}

// BuildEndpoint builds the relationship endpoint URL
//
// Returns:
//   - For single relationship with full objects: "{baseEndpoint}/{id}/{relationship}"
//   - For single relationship with descriptors: "{baseEndpoint}/{id}/relationships/{relationship}"
//   - For query parameter mode: "{baseEndpoint}/{id}"
//
// Returns an error if:
//   - Base endpoint is empty
//   - ID is empty
//   - No relationships specified when not in query parameter mode
//   - Multiple relationships specified when not in query parameter mode
func (rb *RelationshipBuilder) BuildEndpoint() (string, error) {
	if rb.baseEndpoint == "" {
		return "", fmt.Errorf("base endpoint is required")
	}
	if rb.id == "" {
		return "", fmt.Errorf("resource ID is required")
	}

	// If using query parameter mode, return base endpoint
	if rb.includeInQuery {
		return fmt.Sprintf("%s/%s", rb.baseEndpoint, rb.id), nil
	}

	// For endpoint mode, we need exactly one relationship
	if len(rb.relationships) == 0 {
		return "", fmt.Errorf("at least one relationship is required for endpoint mode")
	}
	if len(rb.relationships) > 1 {
		return "", fmt.Errorf("only one relationship can be specified for endpoint mode, use AsQueryParameter() for multiple relationships")
	}

	relationship := rb.relationships[0]

	// Build URL based on endpoint type
	switch rb.endpointType {
	case RelationshipTypeFull:
		// Full objects: {baseEndpoint}/{id}/{relationship}
		return fmt.Sprintf("%s/%s/%s", rb.baseEndpoint, rb.id, relationship), nil
	case RelationshipTypeDescriptor:
		// Descriptors only: {baseEndpoint}/{id}/relationships/{relationship}
		return fmt.Sprintf("%s/%s/relationships/%s", rb.baseEndpoint, rb.id, relationship), nil
	default:
		return "", fmt.Errorf("invalid endpoint type")
	}
}

// BuildQueryParams builds the query parameters for relationships
//
// Returns:
//   - A map with "relationships" key containing comma-separated relationship names
//   - Empty map if no relationships specified or not in query parameter mode
func (rb *RelationshipBuilder) BuildQueryParams() map[string]string {
	params := make(map[string]string)

	if rb.includeInQuery && len(rb.relationships) > 0 {
		params["relationships"] = strings.Join(rb.relationships, ",")
	}

	return params
}

// Build builds both the endpoint and query parameters
//
// Returns:
//   - endpoint: The relationship endpoint URL
//   - queryParams: Query parameters (may be empty)
//   - error: Any validation errors
func (rb *RelationshipBuilder) Build() (endpoint string, queryParams map[string]string, err error) {
	endpoint, err = rb.BuildEndpoint()
	if err != nil {
		return "", nil, err
	}

	queryParams = rb.BuildQueryParams()
	return endpoint, queryParams, nil
}

// BuildRelationshipEndpoint is a convenience function to build a relationship endpoint URL
//
// Parameters:
//   - baseEndpoint: The API endpoint constant (e.g., EndpointFiles="/files", EndpointDomains="/domains")
//   - id: The resource identifier
//   - relationship: The relationship name
//   - descriptorsOnly: If true, returns descriptor endpoint; if false, returns full objects endpoint
//
// Example:
//
//	endpoint := client.BuildRelationshipEndpoint("/files", "abc123", "comments", false)
//	// Returns: "/files/abc123/comments"
//
//	endpoint := client.BuildRelationshipEndpoint("/files", "abc123", "comments", true)
//	// Returns: "/files/abc123/relationships/comments"
func BuildRelationshipEndpoint(baseEndpoint, id, relationship string, descriptorsOnly bool) (string, error) {
	rb := NewRelationshipBuilder(baseEndpoint, id).WithRelationship(relationship)

	if descriptorsOnly {
		rb.AsDescriptorsOnly()
	} else {
		rb.AsFullObjects()
	}

	return rb.BuildEndpoint()
}

// BuildRelationshipQueryParam is a convenience function to build a relationships query parameter
//
// Parameters:
//   - relationships: One or more relationship names to include
//
// Returns:
//   - A comma-separated string of relationship names
//
// Example:
//
//	param := client.BuildRelationshipQueryParam("comments", "votes", "analyses")
//	// Returns: "comments,votes,analyses"
func BuildRelationshipQueryParam(relationships ...string) string {
	filtered := make([]string, 0, len(relationships))
	for _, rel := range relationships {
		if rel != "" {
			filtered = append(filtered, rel)
		}
	}
	return strings.Join(filtered, ",")
}
