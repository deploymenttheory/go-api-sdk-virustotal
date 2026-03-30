package yara_rules

import (
	"context"
	"fmt"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/constants"
	"resty.dev/v3"
)

// Service handles communication with the YARA rules
// related methods of the VirusTotal API.
//
// VirusTotal API docs: https://docs.virustotal.com/reference/list-crowdsourced-yara-rules
type Service struct {
	client client.Client
}

// NewService creates a new YARA rules service
func NewService(c client.Client) *Service {
	return &Service{
		client: c,
	}
}

// =============================================================================
// YARA Rule Operations
// =============================================================================

// ListYaraRules lists crowdsourced YARA rules
// URL: GET https://www.virustotal.com/api/v3/yara_rules
// Query Params: filter (optional), order (optional), limit (optional), cursor (optional)
// Note: Requires VT Premium/Enterprise privileges (VT Hunting)
// https://docs.virustotal.com/reference/list-crowdsourced-yara-rules
func (s *Service) ListYaraRules(ctx context.Context, opts *ListYaraRulesOptions) (*YaraRulesResponse, *resty.Response, error) {
	endpoint := EndpointYaraRules

	builder := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON)

	if opts != nil {
		if opts.Filter != "" {
			builder = builder.SetQueryParam("filter", opts.Filter)
		}
		if opts.Order != "" {
			builder = builder.SetQueryParam("order", opts.Order)
		}
		if opts.Limit > 0 {
			builder = builder.SetQueryParam("limit", fmt.Sprintf("%d", opts.Limit))
		}
		if opts.Cursor != "" {
			builder = builder.SetQueryParam("cursor", opts.Cursor)
		}
	}

	var result YaraRulesResponse
	resp, err := builder.SetResult(&result).Get(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// GetYaraRule retrieves a specific YARA rule by ID
// URL: GET https://www.virustotal.com/api/v3/yara_rules/{id}
// Note: Requires VT Premium/Enterprise privileges (VT Hunting)
// https://docs.virustotal.com/reference/get-a-crowdsourced-yara-rule
func (s *Service) GetYaraRule(ctx context.Context, ruleID string) (*YaraRuleResponse, *resty.Response, error) {
	if err := ValidateYaraRuleID(ruleID); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointYaraRules, ruleID)

	var result YaraRuleResponse
	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetResult(&result).
		Get(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// GetObjectsRelatedToYaraRule retrieves objects related to a YARA rule
// URL: GET https://www.virustotal.com/api/v3/yara_rules/{id}/{relationship}
// Query Params: limit (optional), cursor (optional)
// Note: Requires VT Premium/Enterprise privileges (VT Hunting)
// https://docs.virustotal.com/reference/crowdsourced-yara-rule-relationship-endpoint
func (s *Service) GetObjectsRelatedToYaraRule(ctx context.Context, ruleID string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *resty.Response, error) {
	if err := ValidateYaraRuleID(ruleID); err != nil {
		return nil, nil, err
	}
	if err := ValidateRelationship(relationship); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s/%s", EndpointYaraRules, ruleID, relationship)

	builder := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON)

	if opts != nil {
		if opts.Limit > 0 {
			builder = builder.SetQueryParam("limit", fmt.Sprintf("%d", opts.Limit))
		}
		if opts.Cursor != "" {
			builder = builder.SetQueryParam("cursor", opts.Cursor)
		}
	}

	var result RelatedObjectsResponse
	resp, err := builder.SetResult(&result).Get(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// GetObjectDescriptorsRelatedToYaraRule retrieves object descriptors related to a YARA rule
// URL: GET https://www.virustotal.com/api/v3/yara_rules/{id}/relationships/{relationship}
// Query Params: limit (optional), cursor (optional)
// Note: Requires VT Premium/Enterprise privileges (VT Hunting)
// https://docs.virustotal.com/reference/crowdsourced-yara-rule-relationship-descriptors-endpoint
func (s *Service) GetObjectDescriptorsRelatedToYaraRule(ctx context.Context, ruleID string, relationship string, opts *GetRelatedObjectsOptions) (*ObjectDescriptorsResponse, *resty.Response, error) {
	if err := ValidateYaraRuleID(ruleID); err != nil {
		return nil, nil, err
	}
	if err := ValidateRelationship(relationship); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s/relationships/%s", EndpointYaraRules, ruleID, relationship)

	builder := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON)

	if opts != nil {
		if opts.Limit > 0 {
			builder = builder.SetQueryParam("limit", fmt.Sprintf("%d", opts.Limit))
		}
		if opts.Cursor != "" {
			builder = builder.SetQueryParam("cursor", opts.Cursor)
		}
	}

	var result ObjectDescriptorsResponse
	resp, err := builder.SetResult(&result).Get(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}
