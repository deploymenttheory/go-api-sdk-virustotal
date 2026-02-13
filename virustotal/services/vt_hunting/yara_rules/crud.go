package yara_rules

import (
	"context"
	"fmt"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/interfaces"
)

type (
	// YaraRulesServiceInterface defines the interface for YARA rules operations
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference
	YaraRulesServiceInterface interface {
		// ListYaraRules lists crowdsourced YARA rules
		//
		// Returns a list of crowdsourced YARA rules available in VirusTotal. You can filter
		// rules by various attributes and control the order and pagination of results.
		//
		// Filter parameter examples:
		// - enabled:true - Get only enabled rules
		// - name:foo - Search for rules with "foo" in their name or meta values
		// - author:author_name - Filter by author
		// - tag:malware - Filter by tag
		// - creation_date:2023-01-01+ - Rules created after date
		//
		// Multiple filters can be combined with spaces.
		//
		// Order parameter controls sorting (prefix with + for ascending, - for descending):
		// - matches, creation_date, included_date, modification_date
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/list-crowdsourced-yara-rules
		ListYaraRules(ctx context.Context, opts *ListYaraRulesOptions) (*YaraRulesResponse, *interfaces.Response, error)

		// GetYaraRule retrieves a specific YARA rule by ID
		//
		// Returns detailed information about a crowdsourced YARA rule, including its content,
		// metadata, author, tags, and statistics.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-a-crowdsourced-yara-rule
		GetYaraRule(ctx context.Context, ruleID string) (*YaraRuleResponse, *interfaces.Response, error)

		// GetObjectsRelatedToYaraRule retrieves objects related to a YARA rule
		//
		// Returns objects related to the YARA rule through the specified relationship.
		// Currently supports the "files" relationship which returns files that match the rule.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/crowdsourced-yara-rule-relationship-endpoint
		GetObjectsRelatedToYaraRule(ctx context.Context, ruleID string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *interfaces.Response, error)

		// GetObjectDescriptorsRelatedToYaraRule retrieves object descriptors related to a YARA rule
		//
		// Returns object descriptors (IDs and context attributes only) for objects related to
		// the YARA rule. This is faster than GetObjectsRelatedToYaraRule as it returns only
		// minimal information.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/crowdsourced-yara-rule-relationship-descriptors-endpoint
		GetObjectDescriptorsRelatedToYaraRule(ctx context.Context, ruleID string, relationship string, opts *GetRelatedObjectsOptions) (*ObjectDescriptorsResponse, *interfaces.Response, error)
	}

	// Service handles communication with the YARA rules
	// related methods of the VirusTotal API.
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference/list-crowdsourced-yara-rules
	Service struct {
		client interfaces.HTTPClient
	}
)

// NewService creates a new YARA rules service
func NewService(client interfaces.HTTPClient) *Service {
	return &Service{
		client: client,
	}
}

// =============================================================================
// YARA Rule Operations
// =============================================================================

// ListYaraRules lists crowdsourced YARA rules
// URL: GET https://www.virustotal.com/api/v3/yara_rules
// Query Params: filter (optional), order (optional), limit (optional), cursor (optional)
// https://docs.virustotal.com/reference/list-crowdsourced-yara-rules
func (s *Service) ListYaraRules(ctx context.Context, opts *ListYaraRulesOptions) (*YaraRulesResponse, *interfaces.Response, error) {
	endpoint := EndpointYaraRules
	headers := map[string]string{
		"Accept": "application/json",
	}

	queryParams := make(map[string]string)
	if opts != nil {
		if opts.Filter != "" {
			queryParams["filter"] = opts.Filter
		}
		if opts.Order != "" {
			queryParams["order"] = opts.Order
		}
		if opts.Limit > 0 {
			queryParams["limit"] = fmt.Sprintf("%d", opts.Limit)
		}
		if opts.Cursor != "" {
			queryParams["cursor"] = opts.Cursor
		}
	}

	var result YaraRulesResponse
	resp, err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// GetYaraRule retrieves a specific YARA rule by ID
// URL: GET https://www.virustotal.com/api/v3/yara_rules/{id}
// https://docs.virustotal.com/reference/get-a-crowdsourced-yara-rule
func (s *Service) GetYaraRule(ctx context.Context, ruleID string) (*YaraRuleResponse, *interfaces.Response, error) {
	if err := ValidateYaraRuleID(ruleID); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointYaraRules, ruleID)
	headers := map[string]string{
		"Accept": "application/json",
	}

	var result YaraRuleResponse
	resp, err := s.client.Get(ctx, endpoint, nil, headers, &result)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// GetObjectsRelatedToYaraRule retrieves objects related to a YARA rule
// URL: GET https://www.virustotal.com/api/v3/yara_rules/{id}/{relationship}
// Query Params: limit (optional), cursor (optional)
// https://docs.virustotal.com/reference/crowdsourced-yara-rule-relationship-endpoint
func (s *Service) GetObjectsRelatedToYaraRule(ctx context.Context, ruleID string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *interfaces.Response, error) {
	if err := ValidateYaraRuleID(ruleID); err != nil {
		return nil, nil, err
	}
	if err := ValidateRelationship(relationship); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s/%s", EndpointYaraRules, ruleID, relationship)
	headers := map[string]string{
		"Accept": "application/json",
	}

	queryParams := make(map[string]string)
	if opts != nil {
		if opts.Limit > 0 {
			queryParams["limit"] = fmt.Sprintf("%d", opts.Limit)
		}
		if opts.Cursor != "" {
			queryParams["cursor"] = opts.Cursor
		}
	}

	var result RelatedObjectsResponse
	resp, err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// GetObjectDescriptorsRelatedToYaraRule retrieves object descriptors related to a YARA rule
// URL: GET https://www.virustotal.com/api/v3/yara_rules/{id}/relationships/{relationship}
// Query Params: limit (optional), cursor (optional)
// https://docs.virustotal.com/reference/crowdsourced-yara-rule-relationship-descriptors-endpoint
func (s *Service) GetObjectDescriptorsRelatedToYaraRule(ctx context.Context, ruleID string, relationship string, opts *GetRelatedObjectsOptions) (*ObjectDescriptorsResponse, *interfaces.Response, error) {
	if err := ValidateYaraRuleID(ruleID); err != nil {
		return nil, nil, err
	}
	if err := ValidateRelationship(relationship); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s/relationships/%s", EndpointYaraRules, ruleID, relationship)
	headers := map[string]string{
		"Accept": "application/json",
	}

	queryParams := make(map[string]string)
	if opts != nil {
		if opts.Limit > 0 {
			queryParams["limit"] = fmt.Sprintf("%d", opts.Limit)
		}
		if opts.Cursor != "" {
			queryParams["cursor"] = opts.Cursor
		}
	}

	var result ObjectDescriptorsResponse
	resp, err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}
