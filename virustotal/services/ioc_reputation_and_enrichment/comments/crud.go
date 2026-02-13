package comments

import (
	"context"
	"fmt"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/interfaces"
)

type (
	// CommentsServiceInterface defines the interface for comment operations
	//
	// VirusTotal API docs: https://docs.virustotal.com/reference/comments-api
	CommentsServiceInterface interface {
		// GetLatestComments retrieves the latest comments added to VirusTotal
		//
		// Returns information about the latest comments added to VirusTotal. You can filter
		// comments by tag using the filter parameter (e.g. filter=tag:malware). Results are paginated.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-comments
		GetLatestComments(ctx context.Context, opts *GetCommentsOptions) (*GetCommentsResponse, *interfaces.Response, error)

		// GetComment retrieves a comment by its ID
		//
		// Returns the full details of a comment object identified by its ID.
		// Comment IDs follow the format {prefix}-{item_id}-{random}, where prefix indicates
		// the resource type (d=domain, f=file, g=graph, i=IP, u=URL).
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/get-comment
		GetComment(ctx context.Context, commentID string) (*GetCommentResponse, *interfaces.Response, error)

		// DeleteComment deletes a comment
		//
		// Deletes a comment identified by its ID. Only the comment author or VirusTotal
		// administrators can delete comments.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/comment-id-delete
		DeleteComment(ctx context.Context, commentID string) (*interfaces.Response, error)

		// GetObjectsRelatedToComment retrieves objects related to a comment
		//
		// Returns objects related to a comment based on the specified relationship type.
		// Supported relationships include: author. Results are paginated.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/comments-relationships
		GetObjectsRelatedToComment(ctx context.Context, commentID string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *interfaces.Response, error)

		// GetObjectDescriptorsRelatedToComment retrieves object descriptors (IDs only) related to a comment
		//
		// Returns lightweight object descriptors with just IDs and context attributes instead of full objects.
		// This is more efficient when you only need to know which objects are related without fetching all attributes.
		// Supported relationships are the same as GetObjectsRelatedToComment.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/comments-relationships-ids
		GetObjectDescriptorsRelatedToComment(ctx context.Context, commentID string, relationship string, opts *GetRelatedObjectsOptions) (*ObjectDescriptorsResponse, *interfaces.Response, error)

		// AddVoteToComment adds a vote to a comment
		//
		// Posts a vote for a comment. The vote can be positive (useful), negative (not useful),
		// or marked as abuse. Each user can only vote once per comment, and subsequent votes
		// will update the previous vote.
		//
		// VirusTotal API docs: https://docs.virustotal.com/reference/vote-comment
		AddVoteToComment(ctx context.Context, commentID string, positive int, negative int, abuse int) (*AddVoteResponse, *interfaces.Response, error)
	}

	// Service implements the CommentsServiceInterface
	Service struct {
		client interfaces.HTTPClient
	}
)

var _ CommentsServiceInterface = (*Service)(nil)

func NewService(client interfaces.HTTPClient) *Service {
	return &Service{
		client: client,
	}
}

// =============================================================================
// Get Latest Comments Operations
// =============================================================================

// GetLatestComments retrieves the latest comments added to VirusTotal
// URL: GET https://www.virustotal.com/api/v3/comments
// https://docs.virustotal.com/reference/get-comments
func (s *Service) GetLatestComments(ctx context.Context, opts *GetCommentsOptions) (*GetCommentsResponse, *interfaces.Response, error) {
	endpoint := EndpointComments

	queryParams := make(map[string]string)
	if opts != nil {
		if opts.Filter != "" {
			queryParams["filter"] = opts.Filter
		}
		if opts.Limit > 0 {
			queryParams["limit"] = fmt.Sprintf("%d", opts.Limit)
		}
		if opts.Cursor != "" {
			queryParams["cursor"] = opts.Cursor
		}
	}

	headers := map[string]string{
		"Accept": "application/json",
	}

	var result GetCommentsResponse
	resp, err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
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
func (s *Service) GetComment(ctx context.Context, commentID string) (*GetCommentResponse, *interfaces.Response, error) {
	if err := ValidateCommentID(commentID); err != nil {
		return nil, nil, err
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointComments, commentID)

	headers := map[string]string{
		"Accept": "application/json",
	}

	var result GetCommentResponse
	resp, err := s.client.Get(ctx, endpoint, nil, headers, &result)
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
func (s *Service) DeleteComment(ctx context.Context, commentID string) (*interfaces.Response, error) {
	if err := ValidateCommentID(commentID); err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/%s", EndpointComments, commentID)

	headers := map[string]string{
		"Accept": "application/json",
	}

	resp, err := s.client.Delete(ctx, endpoint, nil, headers, nil)
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
func (s *Service) GetObjectsRelatedToComment(ctx context.Context, commentID string, relationship string, opts *GetRelatedObjectsOptions) (*RelatedObjectsResponse, *interfaces.Response, error) {
	if err := ValidateCommentID(commentID); err != nil {
		return nil, nil, err
	}

	if relationship == "" {
		return nil, client.NewEmptyResponse(), fmt.Errorf("relationship is required")
	}

	endpoint, err := client.BuildRelationshipEndpoint(EndpointComments, commentID, relationship, false)
	if err != nil {
		return nil, client.NewEmptyResponse(), fmt.Errorf("failed to build relationship endpoint: %w", err)
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

	headers := map[string]string{
		"Accept": "application/json",
	}

	var result RelatedObjectsResponse
	resp, err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}

// GetObjectDescriptorsRelatedToComment retrieves object descriptors related to a comment
// URL: GET https://www.virustotal.com/api/v3/comments/{id}/relationships/{relationship}
// https://docs.virustotal.com/reference/comments-relationships-ids
func (s *Service) GetObjectDescriptorsRelatedToComment(ctx context.Context, commentID string, relationship string, opts *GetRelatedObjectsOptions) (*ObjectDescriptorsResponse, *interfaces.Response, error) {
	if err := ValidateCommentID(commentID); err != nil {
		return nil, nil, err
	}

	if relationship == "" {
		return nil, client.NewEmptyResponse(), fmt.Errorf("relationship is required")
	}

	endpoint, err := client.BuildRelationshipEndpoint(EndpointComments, commentID, relationship, true)
	if err != nil {
		return nil, client.NewEmptyResponse(), fmt.Errorf("failed to build relationship endpoint: %w", err)
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

	headers := map[string]string{
		"Accept": "application/json",
	}

	var result ObjectDescriptorsResponse
	resp, err := s.client.Get(ctx, endpoint, queryParams, headers, &result)
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
func (s *Service) AddVoteToComment(ctx context.Context, commentID string, positive int, negative int, abuse int) (*AddVoteResponse, *interfaces.Response, error) {
	if err := ValidateCommentID(commentID); err != nil {
		return nil, nil, err
	}

	// Validate vote values
	if positive < 0 || negative < 0 || abuse < 0 {
		return nil, client.NewEmptyResponse(), fmt.Errorf("vote values cannot be negative")
	}

	endpoint := fmt.Sprintf("%s/%s/vote", EndpointComments, commentID)

	requestBody := AddVoteRequest{
		Data: CommentVotes{
			Positive: positive,
			Negative: negative,
			Abuse:    abuse,
		},
	}

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	var result AddVoteResponse
	resp, err := s.client.Post(ctx, endpoint, requestBody, headers, &result)
	if err != nil {
		return nil, resp, err
	}

	return &result, resp, nil
}
