package attack_tactics

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/constants"
	"resty.dev/v3"
)

// Service handles communication with the attack tactics
// related methods of the VirusTotal API.
//
// VirusTotal API docs: https://docs.virustotal.com/reference/attack-tactics
type Service struct {
	client client.Client
}

// NewService creates a new attack tactics service
func NewService(c client.Client) *Service {
	return &Service{
		client: c,
	}
}

// GetAttackTactic retrieves an attack tactic object by its ID
// URL: GET https://www.virustotal.com/api/v3/attack_tactics/{id}
// https://docs.virustotal.com/reference/get-attack-tactics
func (s *Service) GetAttackTactic(ctx context.Context, id string) (*AttackTacticResponse, *resty.Response, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("attack tactic ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointAttackTactics, id)

	var result AttackTacticResponse
	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		SetResult(&result).
		Get(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// GetObjectsRelatedToAttackTactic retrieves objects related to an attack tactic
// URL: GET https://www.virustotal.com/api/v3/attack_tactics/{id}/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/get-attack-tactics-relationship
func (s *Service) GetObjectsRelatedToAttackTactic(ctx context.Context, id string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *resty.Response, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("attack tactic ID is required")
	}
	if relationship == "" {
		return nil, nil, fmt.Errorf("relationship is required")
	}

	// Use RelationshipBuilder to construct the endpoint for full objects
	endpoint, err := client.BuildRelationshipEndpoint(EndpointAttackTactics, id, relationship, false)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build relationship endpoint: %w", err)
	}

	if opts != nil {
		builder := s.client.NewRequest(ctx).
			SetHeader("Accept", constants.ApplicationJSON).
			SetHeader("Content-Type", constants.ApplicationJSON)

		if opts.Limit > 0 {
			builder = builder.SetQueryParam("limit", fmt.Sprintf("%d", opts.Limit))
		}
		if opts.Cursor != "" {
			builder = builder.SetQueryParam("cursor", opts.Cursor)
		}

		var result RelatedObjectsResponse
		resp, err := builder.SetResult(&result).Get(endpoint)
		if err != nil {
			return nil, resp, err
		}

		return &result, resp, nil
	}

	var allObjects []RelatedObject

	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		GetPaginated(endpoint, func(pageData []byte) error {
			var pageResponse RelatedObjectsResponse
			if err := json.Unmarshal(pageData, &pageResponse); err != nil {
				return fmt.Errorf("failed to unmarshal page: %w", err)
			}
			allObjects = append(allObjects, pageResponse.Data...)
			return nil
		})

	if err != nil {
		return nil, resp, err
	}

	return &RelatedObjectsResponse{
		Data: allObjects,
	}, resp, nil
}

// GetObjectDescriptorsRelatedToAttackTactic retrieves object descriptors (IDs only) related to an attack tactic
// URL: GET https://www.virustotal.com/api/v3/attack_tactics/{id}/relationships/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/get-attack-tactics-relationship-descriptor
func (s *Service) GetObjectDescriptorsRelatedToAttackTactic(ctx context.Context, id string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectDescriptorsResponse, *resty.Response, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("attack tactic ID is required")
	}
	if relationship == "" {
		return nil, nil, fmt.Errorf("relationship is required")
	}

	endpoint, err := client.BuildRelationshipEndpoint(EndpointAttackTactics, id, relationship, true)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build relationship endpoint: %w", err)
	}

	if opts != nil {
		builder := s.client.NewRequest(ctx).
			SetHeader("Accept", constants.ApplicationJSON).
			SetHeader("Content-Type", constants.ApplicationJSON)

		if opts.Limit > 0 {
			builder = builder.SetQueryParam("limit", fmt.Sprintf("%d", opts.Limit))
		}
		if opts.Cursor != "" {
			builder = builder.SetQueryParam("cursor", opts.Cursor)
		}

		var result RelatedObjectDescriptorsResponse
		resp, err := builder.SetResult(&result).Get(endpoint)
		if err != nil {
			return nil, resp, err
		}

		return &result, resp, nil
	}

	var allDescriptors []ObjectDescriptor

	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		GetPaginated(endpoint, func(pageData []byte) error {
			var pageResponse RelatedObjectDescriptorsResponse
			if err := json.Unmarshal(pageData, &pageResponse); err != nil {
				return fmt.Errorf("failed to unmarshal page: %w", err)
			}
			allDescriptors = append(allDescriptors, pageResponse.Data...)
			return nil
		})

	if err != nil {
		return nil, resp, err
	}

	return &RelatedObjectDescriptorsResponse{
		Data: allDescriptors,
	}, resp, nil
}
