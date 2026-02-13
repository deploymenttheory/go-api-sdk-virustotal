package attack_techniques

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/interfaces"
)

type (
	// AttackTechniquesServiceInterface defines the interface for attack techniques operations
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference/attack-techniques
	AttackTechniquesServiceInterface interface {
		// GetAttackTechnique retrieves an attack technique object by its ID
		//
		// Returns a MITRE ATT&CK technique object including name, description, STIX ID,
		// and link to the MITRE ATT&CK framework. Technique IDs follow the format T#### or T####.### (e.g., T1110, T1110.001).
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-attack-techniques
		GetAttackTechnique(ctx context.Context, id string) (*AttackTechniqueResponse, *interfaces.Response, error)

		// GetObjectsRelatedToAttackTechnique retrieves objects related to an attack technique
		//
		// Returns objects related to an attack technique based on the specified relationship type.
		// Supported relationships include: attack_tactics, parent_technique, revoking_technique, subtechniques, threat_actors.
		// Results are paginated.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-attack-techniques-relationship
		GetObjectsRelatedToAttackTechnique(ctx context.Context, id string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *interfaces.Response, error)

		// GetObjectDescriptorsRelatedToAttackTechnique retrieves object descriptors (IDs only) related to an attack technique
		//
		// Returns lightweight object descriptors with just IDs and context attributes instead of full objects.
		// This is more efficient when you only need to know which objects are related without fetching all attributes.
		// Supported relationships are the same as GetObjectsRelatedToAttackTechnique.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-attack-techniques-relationship-descriptor
		GetObjectDescriptorsRelatedToAttackTechnique(ctx context.Context, id string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectDescriptorsResponse, *interfaces.Response, error)
	}

	// Service handles communication with the attack techniques
	// related methods of the VirusTotal API.
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference/attack-techniques
	Service struct {
		client interfaces.HTTPClient
	}
)

// Ensure Service implements AttackTechniquesServiceInterface
var _ AttackTechniquesServiceInterface = (*Service)(nil)

// NewService creates a new attack techniques service
func NewService(client interfaces.HTTPClient) *Service {
	return &Service{
		client: client,
	}
}

// GetAttackTechnique retrieves an attack technique object by its ID
// URL: GET https://www.virustotal.com/api/v3/attack_techniques/{id}
// https://docs.virustotal.com/reference/get-attack-techniques
func (s *Service) GetAttackTechnique(ctx context.Context, id string) (*AttackTechniqueResponse, *interfaces.Response, error) {
	if id == "" {
		return nil, client.NewEmptyResponse(), fmt.Errorf("attack technique ID is required")
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointAttackTechniques, id)

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result AttackTechniqueResponse
	resp, err := s.client.Get(ctx, endpoint, nil, headers, &result)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// GetObjectsRelatedToAttackTechnique retrieves objects related to an attack technique
// URL: GET https://www.virustotal.com/api/v3/attack_techniques/{id}/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/get-attack-techniques-relationship
func (s *Service) GetObjectsRelatedToAttackTechnique(ctx context.Context, id string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *interfaces.Response, error) {
	if id == "" {
		return nil, client.NewEmptyResponse(), fmt.Errorf("attack technique ID is required")
	}
	if relationship == "" {
		return nil, client.NewEmptyResponse(), fmt.Errorf("relationship is required")
	}

	// Use RelationshipBuilder to construct the endpoint for full objects
	endpoint, err := client.BuildRelationshipEndpoint(EndpointAttackTechniques, id, relationship, false)
	if err != nil {
		return nil, client.NewEmptyResponse(), fmt.Errorf("failed to build relationship endpoint: %w", err)
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

// GetObjectDescriptorsRelatedToAttackTechnique retrieves object descriptors (IDs only) related to an attack technique
// URL: GET https://www.virustotal.com/api/v3/attack_techniques/{id}/relationships/{relationship}
// Query Params: limit (optional), cursor (optional)
// Pagination: Pass nil opts for automatic pagination (all pages). Provide opts for manual pagination (single page).
// https://docs.virustotal.com/reference/get-attack-techniques-relationship-descriptor
func (s *Service) GetObjectDescriptorsRelatedToAttackTechnique(ctx context.Context, id string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectDescriptorsResponse, *interfaces.Response, error) {
	if id == "" {
		return nil, client.NewEmptyResponse(), fmt.Errorf("attack technique ID is required")
	}
	if relationship == "" {
		return nil, client.NewEmptyResponse(), fmt.Errorf("relationship is required")
	}

	endpoint, err := client.BuildRelationshipEndpoint(EndpointAttackTechniques, id, relationship, true)
	if err != nil {
		return nil, client.NewEmptyResponse(), fmt.Errorf("failed to build relationship endpoint: %w", err)
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
