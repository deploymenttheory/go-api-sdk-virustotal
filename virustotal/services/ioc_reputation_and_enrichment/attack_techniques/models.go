package attack_techniques

import (
	attack_techniques_relationships "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models/relationships/attack_techniques"
)

// AttackTechniqueResponse represents the response from GET /attack_techniques/{id}
type AttackTechniqueResponse struct {
	Data  AttackTechnique `json:"data"`
	Links Links           `json:"links,omitempty"`
}

// AttackTechnique represents a MITRE ATT&CK adversary technique
type AttackTechnique struct {
	Type          string                    `json:"type"`
	ID            string                    `json:"id"`
	Attributes    AttackTechniqueAttributes `json:"attributes"`
	Links         Links                     `json:"links,omitempty"`
	Relationships map[string]any            `json:"relationships,omitempty"`
}

// AttackTechniqueAttributes contains the attributes of an attack technique
type AttackTechniqueAttributes struct {
	CreationDate         int64          `json:"creation_date"`
	Description          string         `json:"description"`
	Info                 map[string]any `json:"info,omitempty"`
	LastModificationDate int64          `json:"last_modification_date"`
	Link                 string         `json:"link"`
	Name                 string         `json:"name"`
	Revoked              bool           `json:"revoked"`
	StixID               string         `json:"stix_id"`
}

// Links represents the links section of an object
type Links struct {
	Self string `json:"self"`           // URL to this object
	Next string `json:"next,omitempty"` // Next page URL
}

// RelatedObjectsResponse represents the response from GET /attack_techniques/{id}/{relationship}
type RelatedObjectsResponse struct {
	Data  []RelatedObject `json:"data"`
	Links Links           `json:"links,omitempty"`
	Meta  Meta            `json:"meta,omitempty"`
}

// RelatedObject represents an object related to an attack technique
type RelatedObject struct {
	Type              string         `json:"type"`
	ID                string         `json:"id"`
	Links             *Links         `json:"links,omitempty"`
	Attributes        map[string]any `json:"attributes,omitempty"`
	ContextAttributes map[string]any `json:"context_attributes,omitempty"`
}

// RelatedObjectDescriptorsResponse represents the response from GET /attack_techniques/{id}/relationships/{relationship}
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

// AttackTacticsResponse represents the response for the attack_tactics relationship
type AttackTacticsResponse = attack_techniques_relationships.AttackTacticsResponse

// ParentTechniqueResponse represents the response for the parent_technique relationship
type ParentTechniqueResponse = attack_techniques_relationships.ParentTechniqueResponse

// RevokingTechniqueResponse represents the response for the revoking_technique relationship
type RevokingTechniqueResponse = attack_techniques_relationships.RevokingTechniqueResponse

// SubtechniquesResponse represents the response for the subtechniques relationship
type SubtechniquesResponse = attack_techniques_relationships.SubtechniquesResponse

// ThreatActorsResponse represents the response for the threat_actors relationship
type ThreatActorsResponse = attack_techniques_relationships.ThreatActorsResponse
