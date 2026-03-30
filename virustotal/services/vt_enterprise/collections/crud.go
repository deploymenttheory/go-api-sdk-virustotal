package collections

import (
	"context"
	"fmt"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/constants"
	"resty.dev/v3"
)

// Service handles communication with the Collections
// related methods of the VirusTotal API.
//
// VirusTotal API docs: https://docs.virustotal.com/reference/collections-create
type Service struct {
	client client.Client
}

func NewService(c client.Client) *Service {
	return &Service{
		client: c,
	}
}

// =============================================================================
// Collection CRUD Operations
// =============================================================================

// CreateCollection creates a new collection
// URL: POST https://www.virustotal.com/api/v3/collections
// Body: JSON with collection name, description, and relationships or raw_items
// https://docs.virustotal.com/reference/collections-create
func (s *Service) CreateCollection(ctx context.Context, req *CreateCollectionRequest) (*CollectionResponse, *resty.Response, error) {
	if err := ValidateCreateCollectionRequest(req); err != nil {
		return nil, nil, err
	}

	endpoint := EndpointCollections

	var result CollectionResponse
	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		SetBody(req).
		SetResult(&result).
		Post(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// GetCollection retrieves a collection by ID
// URL: GET https://www.virustotal.com/api/v3/collections/{id}
// https://docs.virustotal.com/reference/collections-get
func (s *Service) GetCollection(ctx context.Context, collectionID string) (*CollectionResponse, *resty.Response, error) {
	if err := ValidateCollectionID(collectionID); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointCollections, collectionID)

	var result CollectionResponse
	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetResult(&result).
		Get(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// UpdateCollection updates a collection's attributes or adds new elements
// URL: PATCH https://www.virustotal.com/api/v3/collections/{id}
// Body: JSON with updated name/description or raw_items
// https://docs.virustotal.com/reference/collections-update
func (s *Service) UpdateCollection(ctx context.Context, collectionID string, req *UpdateCollectionRequest) (*CollectionResponse, *resty.Response, error) {
	if err := ValidateCollectionID(collectionID); err != nil {
		return nil, nil, err
	}
	if err := ValidateUpdateCollectionRequest(req); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointCollections, collectionID)

	var result CollectionResponse
	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		SetBody(req).
		SetResult(&result).
		Patch(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// DeleteCollection deletes a collection
// URL: DELETE https://www.virustotal.com/api/v3/collections/{id}
// https://docs.virustotal.com/reference/collections-delete
func (s *Service) DeleteCollection(ctx context.Context, collectionID string) (*DeleteCollectionResponse, *resty.Response, error) {
	if err := ValidateCollectionID(collectionID); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointCollections, collectionID)

	var result DeleteCollectionResponse
	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetResult(&result).
		Delete(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// =============================================================================
// Comment Operations
// =============================================================================

// GetCommentsOnCollection retrieves comments on a collection
// URL: GET https://www.virustotal.com/api/v3/collections/{id}/comments
// Query Params: limit (optional), cursor (optional)
// https://docs.virustotal.com/reference/collections-comments
func (s *Service) GetCommentsOnCollection(ctx context.Context, collectionID string, opts *GetRelatedObjectsOptions) (*CommentsResponse, *resty.Response, error) {
	if err := ValidateCollectionID(collectionID); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s/comments", EndpointCollections, collectionID)

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

	var result CommentsResponse
	resp, err := builder.SetResult(&result).Get(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// AddCommentToCollection adds a comment to a collection
// URL: POST https://www.virustotal.com/api/v3/collections/{id}/comments
// Body: JSON with comment text (words starting with # become tags)
// https://docs.virustotal.com/reference/collections-comments-create
func (s *Service) AddCommentToCollection(ctx context.Context, collectionID string, comment string) (*AddCommentResponse, *resty.Response, error) {
	if err := ValidateCollectionID(collectionID); err != nil {
		return nil, nil, err
	}
	if err := ValidateCommentText(comment); err != nil {
		return nil, nil, err
	}

	req := &AddCommentRequest{
		Data: AddCommentData{
			Type: "comment",
			Attributes: AddCommentAttributes{
				Text: comment,
			},
		},
	}

	endpoint := fmt.Sprintf("%s/%s/comments", EndpointCollections, collectionID)

	var result AddCommentResponse
	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		SetBody(req).
		SetResult(&result).
		Post(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// =============================================================================
// Relationship Operations
// =============================================================================

// GetObjectsRelatedToCollection retrieves objects related to a collection
// URL: GET https://www.virustotal.com/api/v3/collections/{id}/{relationship}
// Query Params: limit (optional), cursor (optional)
// Note: Some relationships require VT Enterprise license (related_collections, related_references, threat_actors)
// https://docs.virustotal.com/reference/get-collections-relationship
func (s *Service) GetObjectsRelatedToCollection(ctx context.Context, collectionID string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *resty.Response, error) {
	if err := ValidateCollectionID(collectionID); err != nil {
		return nil, nil, err
	}
	if err := ValidateRelationship(relationship); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s/%s", EndpointCollections, collectionID, relationship)

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

// GetObjectDescriptorsRelatedToCollection retrieves object descriptors related to a collection
// URL: GET https://www.virustotal.com/api/v3/collections/{id}/relationships/{relationship}
// Query Params: limit (optional), cursor (optional)
// Note: Some relationships require VT Enterprise license (related_collections, related_references, threat_actors)
// https://docs.virustotal.com/reference/get-collections-relationship-descriptor
func (s *Service) GetObjectDescriptorsRelatedToCollection(ctx context.Context, collectionID string, relationship string, opts *GetRelatedObjectsOptions) (*ObjectDescriptorsResponse, *resty.Response, error) {
	if err := ValidateCollectionID(collectionID); err != nil {
		return nil, nil, err
	}
	if err := ValidateRelationship(relationship); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s/relationships/%s", EndpointCollections, collectionID, relationship)

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

// =============================================================================
// Item Management Operations
// =============================================================================

// AddItemsToCollection adds new items to a collection
// URL: POST https://www.virustotal.com/api/v3/collections/{id}/{relationship}
// Body: JSON array of relationship items (for URLs: use id or url field)
// https://docs.virustotal.com/reference/collections-add-element
func (s *Service) AddItemsToCollection(ctx context.Context, collectionID string, relationship string, req *AddItemsRequest) (*AddItemsResponse, *resty.Response, error) {
	if err := ValidateCollectionID(collectionID); err != nil {
		return nil, nil, err
	}
	if err := ValidateRelationship(relationship); err != nil {
		return nil, nil, err
	}
	if err := ValidateAddItemsRequest(req); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s/%s", EndpointCollections, collectionID, relationship)

	var result AddItemsResponse
	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		SetBody(req).
		SetResult(&result).
		Post(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// DeleteItemsFromCollection deletes items from a collection
// URL: DELETE https://www.virustotal.com/api/v3/collections/{id}/{relationship}
// Body: JSON array of relationship items (for URLs: use id or url field)
// https://docs.virustotal.com/reference/collections-delete-element
func (s *Service) DeleteItemsFromCollection(ctx context.Context, collectionID string, relationship string, req *DeleteItemsRequest) (*DeleteItemsResponse, *resty.Response, error) {
	if err := ValidateCollectionID(collectionID); err != nil {
		return nil, nil, err
	}
	if err := ValidateRelationship(relationship); err != nil {
		return nil, nil, err
	}
	if err := ValidateDeleteItemsRequest(req); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s/%s", EndpointCollections, collectionID, relationship)

	var result DeleteItemsResponse
	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		SetBody(req).
		SetResult(&result).
		Delete(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

