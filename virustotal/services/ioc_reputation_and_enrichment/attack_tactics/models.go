package attack_tactics

import (
	attack_tactics_relationships "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models/relationships/attack_tactics"
)

// AttackTacticResponse represents the response from GET /attack_tactics/{id}
type AttackTacticResponse struct {
	Data  AttackTactic `json:"data"`
	Links Links        `json:"links,omitempty"`
}

// AttackTactic represents a MITRE ATT&CK adversary tactic
type AttackTactic struct {
	Type          string                 `json:"type"`
	ID            string                 `json:"id"`
	Attributes    AttackTacticAttributes `json:"attributes"`
	Links         Links                  `json:"links,omitempty"`
	Relationships map[string]any         `json:"relationships,omitempty"`
}

// AttackTacticAttributes contains the attributes of an attack tactic
type AttackTacticAttributes struct {
	CreationDate         int64  `json:"creation_date"`
	Description          string `json:"description"`
	LastModificationDate int64  `json:"last_modification_date"`
	Link                 string `json:"link"`
	Name                 string `json:"name"`
	StixID               string `json:"stix_id"`
}

// Links represents the links section of an object
type Links struct {
	Self string `json:"self"`           // URL to this object
	Next string `json:"next,omitempty"` // Next page URL
}

// RelatedObjectsResponse represents the response from GET /attack_tactics/{id}/{relationship}
type RelatedObjectsResponse struct {
	Data  []RelatedObject `json:"data"`
	Links Links           `json:"links,omitempty"`
	Meta  Meta            `json:"meta,omitempty"`
}

// RelatedObject represents an object related to an attack tactic
type RelatedObject struct {
	Type              string         `json:"type"`
	ID                string         `json:"id"`
	Links             *Links         `json:"links,omitempty"`
	Attributes        map[string]any `json:"attributes,omitempty"`
	ContextAttributes map[string]any `json:"context_attributes,omitempty"`
}

// RelatedObjectDescriptorsResponse represents the response from GET /attack_tactics/{id}/relationships/{relationship}
type RelatedObjectDescriptorsResponse struct {
	Data  []ObjectDescriptor `json:"data"`
	Links Links              `json:"links,omitempty"`
	Meta  Meta               `json:"meta,omitempty"`
}

// ObjectDescriptor represents a lightweight descriptor for a related object
type ObjectDescriptor struct {
	Type              string         `json:"type"`
	ID                string         `json:"id"`
	ContextAttributes map[string]any `json:"context_attributes,omitempty"`
}

// Meta represents metadata about the response
type Meta struct {
	Count  int    `json:"count,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}

// GetRelatedObjectsOptions contains options for retrieving related objects
type GetRelatedObjectsOptions struct {
	Limit  int    // Number of items per page (default 10, max 40)
	Cursor string // Continuation cursor for pagination
}

// =============================================================================
// Relationship Response Types
// =============================================================================

// AttackTechniquesResponse represents the response for the attack_techniques relationship
type AttackTechniquesResponse = attack_tactics_relationships.AttackTechniquesResponse
