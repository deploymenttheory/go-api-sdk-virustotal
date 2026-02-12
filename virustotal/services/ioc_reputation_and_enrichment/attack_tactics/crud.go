package attack_tactics

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/interfaces"
)

type (
	// AttackTacticsServiceInterface defines the interface for attack tactics operations
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference/attack-tactics
	AttackTacticsServiceInterface interface {
		// GetAttackTactic retrieves an attack tactic object by its ID
		//
		// Returns a MITRE ATT&CK tactic object including name, description, STIX ID,
		// and link to the MITRE ATT&CK framework. Tactic IDs follow the format TA#### (e.g., TA0004).
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-attack-tactics
		GetAttackTactic(ctx context.Context, id string) (*AttackTacticResponse, *interfaces.Response, error)

		// GetObjectsRelatedToAttackTactic retrieves objects related to an attack tactic
		//
		// Returns objects related to an attack tactic based on the specified relationship type.
		// Supported relationships include: attack_techniques. Results are paginated.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-attack-tactics-relationship
		GetObjectsRelatedToAttackTactic(ctx context.Context, id string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *interfaces.Response, error)

		// GetObjectDescriptorsRelatedToAttackTactic retrieves object descriptors (IDs only) related to an attack tactic
		//
		// Returns lightweight object descriptors with just IDs and context attributes instead of full objects.
		// This is more efficient when you only need to know which objects are related without fetching all attributes.
		// Supported relationships are the same as GetObjectsRelatedToAttackTactic.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-attack-tactics-relationship-descriptor
		GetObjectDescriptorsRelatedToAttackTactic(ctx context.Context, id string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectDescriptorsResponse, *interfaces.Response, error)
	}

	// Service handles communication with the attack tactics
	// related methods of the VirusTotal API.
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference/attack-tactics
	Service struct {
		client interfaces.HTTPClient
	}
)

// Ensure Service implements AttackTacticsServiceInterface
var _ AttackTacticsServiceInterface = (*Service)(nil)

// NewService creates a new attack tactics service
func NewService(client interfaces.HTTPClient) *Service {
	return &Service{
		client: client,
	}
}

// GetAttackTactic retrieves an attack tactic object by its ID
// URL: GET https://www.virustotal.com/api/v3/attack_tactics/{id}
// https://docs.virustotal.com/reference/get-attack-tactics
func (s *Service) GetAttackTactic(ctx context.Context, id string) (*AttackTacticResponse, *interfaces.Response, error) {
	if id == "" {
		return nil, nil, fmt.Errorf("attack tactic ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointAttackTactics, id)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result AttackTacticResponse
	resp, err := s.client.Get(ctx, endpoint, nil, headers, &result)
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
func (s *Service) GetObjectsRelatedToAttackTactic(ctx context.Context, id string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *interfaces.Response, error) {
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

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	queryParams := make(map[string]string)

	if opts != nil {
		if opts.Limit > 0 {
			queryParams["limit"] = fmt.Sprintf("%d", opts.Limit)
		}
		if opts.Cursor != "" {
			queryParams["cursor"] = opts.Cursor
		}

		var result RelatedObjectsResponse
		resp, err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
		if err != nil {
			return nil, resp, err
		}

		return &result, resp, nil
	}

	var allObjects []RelatedObject

	resp, err := s.client.GetPaginated(ctx, endpoint, queryParams, headers, func(pageData []byte) error {
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
func (s *Service) GetObjectDescriptorsRelatedToAttackTactic(ctx context.Context, id string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectDescriptorsResponse, *interfaces.Response, error) {
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

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	queryParams := make(map[string]string)

	if opts != nil {
		if opts.Limit > 0 {
			queryParams["limit"] = fmt.Sprintf("%d", opts.Limit)
		}
		if opts.Cursor != "" {
			queryParams["cursor"] = opts.Cursor
		}

		var result RelatedObjectDescriptorsResponse
		resp, err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
		if err != nil {
			return nil, resp, err
		}

		return &result, resp, nil
	}

	var allDescriptors []ObjectDescriptor

	resp, err := s.client.GetPaginated(ctx, endpoint, queryParams, headers, func(pageData []byte) error {
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
