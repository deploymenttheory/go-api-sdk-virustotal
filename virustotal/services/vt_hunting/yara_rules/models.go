package yara_rules

import (
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/shared_models"
)

// =============================================================================
// Common Structures
// =============================================================================

type Links = shared_models.ObjectLinks
type RelatedLinks = shared_models.Links
type Meta = shared_models.Meta

// =============================================================================
// YARA Rule Models
// =============================================================================

// YaraRulesResponse represents a list of YARA rules
type YaraRulesResponse struct {
	Data  []YaraRule   `json:"data"`
	Links RelatedLinks `json:"links,omitempty"`
	Meta  Meta         `json:"meta,omitempty"`
}

// YaraRuleResponse represents a single YARA rule response
type YaraRuleResponse struct {
	Data YaraRule `json:"data"`
}

// YaraRule represents a VirusTotal crowdsourced YARA rule
type YaraRule struct {
	Type       string           `json:"type"`
	ID         string           `json:"id"`
	Links      Links            `json:"links,omitempty"`
	Attributes YaraRuleAttributes `json:"attributes"`
}

// YaraRuleAttributes contains YARA rule attributes
type YaraRuleAttributes struct {
	Name                 string         `json:"name"`
	Tags                 []string       `json:"tags,omitempty"`
	Matches              int            `json:"matches"`
	Author               string         `json:"author,omitempty"`
	Enabled              bool           `json:"enabled"`
	Rule                 string         `json:"rule"`
	CreationDate         int64          `json:"creation_date"`
	Meta                 []YaraRuleMeta `json:"meta,omitempty"`
	LastModificationDate int64          `json:"last_modification_date,omitempty"`
}

// YaraRuleMeta represents metadata key-value pairs in a YARA rule
type YaraRuleMeta struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// =============================================================================
// Related Objects Models
// =============================================================================

// RelatedObjectsResponse represents related objects response
type RelatedObjectsResponse struct {
	Data  []RelatedObject `json:"data"`
	Links RelatedLinks    `json:"links,omitempty"`
	Meta  Meta            `json:"meta,omitempty"`
}

// RelatedObject represents a related object
type RelatedObject struct {
	Type              string                 `json:"type"`
	ID                string                 `json:"id"`
	Links             Links                  `json:"links,omitempty"`
	Attributes        map[string]interface{} `json:"attributes,omitempty"`
	ContextAttributes map[string]interface{} `json:"context_attributes,omitempty"`
}

// ObjectDescriptorsResponse represents object descriptors response
type ObjectDescriptorsResponse struct {
	Data  []ObjectDescriptor `json:"data"`
	Links RelatedLinks       `json:"links,omitempty"`
	Meta  Meta               `json:"meta,omitempty"`
}

// ObjectDescriptor represents an object descriptor
type ObjectDescriptor struct {
	Type              string                 `json:"type"`
	ID                string                 `json:"id"`
	Links             Links                  `json:"links,omitempty"`
	ContextAttributes map[string]interface{} `json:"context_attributes,omitempty"`
}

// =============================================================================
// Options
// =============================================================================

// ListYaraRulesOptions contains options for listing YARA rules
type ListYaraRulesOptions struct {
	Filter string `json:"filter,omitempty"`
	Order  string `json:"order,omitempty"`
	Limit  int    `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}

// GetRelatedObjectsOptions contains options for retrieving related objects
type GetRelatedObjectsOptions struct {
	Limit  int    `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}
