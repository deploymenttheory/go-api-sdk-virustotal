package comments

import (
	"context"
	"fmt"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/constants"
	"resty.dev/v3"
)

// Service implements the CommentsServiceInterface
type Service struct {
	client client.Client
}

func NewService(c client.Client) *Service {
	return &Service{
		client: c,
	}
}

// =============================================================================
// Get Latest Comments Operations
// =============================================================================

// GetLatestComments retrieves the latest comments added to VirusTotal
// URL: GET https://www.virustotal.com/api/v3/comments
// https://docs.virustotal.com/reference/get-comments
func (s *Service) GetLatestComments(ctx context.Context, opts *GetCommentsOptions) (*GetCommentsResponse, *resty.Response, error) {
	endpoint := EndpointComments

	builder := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON)

	if opts != nil {
		if opts.Filter != "" {
			builder = builder.SetQueryParam("filter", opts.Filter)
		}
		if opts.Limit > 0 {
			builder = builder.SetQueryParam("limit", fmt.Sprintf("%d", opts.Limit))
		}
		if opts.Cursor != "" {
			builder = builder.SetQueryParam("cursor", opts.Cursor)
		}
	}

	var result GetCommentsResponse
	resp, err := builder.SetResult(&result).Get(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// =============================================================================
// Get Comment Operations
// =============================================================================

// GetComment retrieves a comment by its ID
// URL: GET https://www.virustotal.com/api/v3/comments/{id}
// https://docs.virustotal.com/reference/get-comment
func (s *Service) GetComment(ctx context.Context, commentID string) (*GetCommentResponse, *resty.Response, error) {
	if err := ValidateCommentID(commentID); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointComments, commentID)

	var result GetCommentResponse
	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetResult(&result).
		Get(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// =============================================================================
// Delete Comment Operations
// =============================================================================

// DeleteComment deletes a comment
// URL: DELETE https://www.virustotal.com/api/v3/comments/{id}
// https://docs.virustotal.com/reference/comment-id-delete
func (s *Service) DeleteComment(ctx context.Context, commentID string) (*resty.Response, error) {
	if err := ValidateCommentID(commentID); err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointComments, commentID)

	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		Delete(endpoint)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

// =============================================================================
// Related Objects Operations
// =============================================================================

// GetObjectsRelatedToComment retrieves objects related to a comment
// URL: GET https://www.virustotal.com/api/v3/comments/{id}/{relationship}
// https://docs.virustotal.com/reference/comments-relationships
func (s *Service) GetObjectsRelatedToComment(ctx context.Context, commentID string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *resty.Response, error) {
	if err := ValidateCommentID(commentID); err != nil {
		return nil, nil, err
	}

	if relationship == "" {
		return nil, nil, fmt.Errorf("relationship is required")
	}

	endpoint, err := client.BuildRelationshipEndpoint(EndpointComments, commentID, relationship, false)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build relationship endpoint: %w", err)
	}

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

// GetObjectDescriptorsRelatedToComment retrieves object descriptors related to a comment
// URL: GET https://www.virustotal.com/api/v3/comments/{id}/relationships/{relationship}
// https://docs.virustotal.com/reference/comments-relationships-ids
func (s *Service) GetObjectDescriptorsRelatedToComment(ctx context.Context, commentID string, relationship string, opts *GetRelatedObjectsOptions) (*ObjectDescriptorsResponse, *resty.Response, error) {
	if err := ValidateCommentID(commentID); err != nil {
		return nil, nil, err
	}

	if relationship == "" {
		return nil, nil, fmt.Errorf("relationship is required")
	}

	endpoint, err := client.BuildRelationshipEndpoint(EndpointComments, commentID, relationship, true)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build relationship endpoint: %w", err)
	}

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
// Vote Operations
// =============================================================================

// AddVoteToComment adds a vote to a comment
// URL: POST https://www.virustotal.com/api/v3/comments/{id}/vote
// https://docs.virustotal.com/reference/vote-comment
func (s *Service) AddVoteToComment(ctx context.Context, commentID string, positive int, negative int, abuse int) (*AddVoteResponse, *resty.Response, error) {
	if err := ValidateCommentID(commentID); err != nil {
		return nil, nil, err
	}

	// Validate vote values
	if positive < 0 || negative < 0 || abuse < 0 {
		return nil, nil, fmt.Errorf("vote values cannot be negative")
	}

	endpoint := fmt.Sprintf("%s/%s/vote", EndpointComments, commentID)

	requestBody := AddVoteRequest{
		Data: CommentVotes{
			Positive: positive,
			Negative: negative,
			Abuse:    abuse,
		},
	}

	var result AddVoteResponse
	resp, err := s.client.NewRequest(ctx).
		SetHeader("Accept", constants.ApplicationJSON).
		SetHeader("Content-Type", constants.ApplicationJSON).
		SetBody(requestBody).
		SetResult(&result).
		Post(endpoint)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}
