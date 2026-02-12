package acceptance

import (
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/urls"
	"github.com/stretchr/testify/assert"
)

// TestAcceptance_URLs_GetURLReport tests retrieving URL information
func TestAcceptance_URLs_GetURLReport(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := urls.NewService(Client)

		LogResponse(t, "Testing GetURLReport with URL ID: %s", Config.KnownURLID)

		result, err := service.GetURLReport(ctx, Config.KnownURLID)
		AssertNoError(t, err, "GetURLReport should not return an error")
		AssertNotNil(t, result, "GetURLReport result should not be nil")

		// Validate response structure
		assert.NotNil(t, result.Data, "URL data should not be nil")
		assert.Equal(t, "url", result.Data.Type, "Response type should be 'url'")
		assert.NotEmpty(t, result.Data.ID, "URL ID should not be empty")
		assert.NotNil(t, result.Data.Attributes, "URL attributes should not be nil")

		// Validate URL attributes
		attrs := result.Data.Attributes
		assert.NotEmpty(t, attrs.URL, "URL should not be empty")
		assert.Contains(t, attrs.URL, "https://", "URL should be HTTPS")
		
		// Validate analysis stats
		assert.NotNil(t, attrs.LastAnalysisStats, "Last analysis stats should not be nil")
		assert.GreaterOrEqual(t, attrs.LastAnalysisStats.Harmless, 0, "Harmless count should be >= 0")
		assert.GreaterOrEqual(t, attrs.LastAnalysisStats.Malicious, 0, "Malicious count should be >= 0")
		assert.GreaterOrEqual(t, attrs.LastAnalysisStats.Suspicious, 0, "Suspicious count should be >= 0")
		assert.GreaterOrEqual(t, attrs.LastAnalysisStats.Undetected, 0, "Undetected count should be >= 0")
		
		// Validate timestamps
		assert.Greater(t, attrs.LastAnalysisDate, int64(0), "Last analysis date should be valid")
		assert.Greater(t, attrs.LastModificationDate, int64(0), "Last modification date should be valid")
		
		// Validate reputation and vote counts
		assert.NotEqual(t, 0, attrs.Reputation, "Reputation should be set")
		assert.NotNil(t, attrs.TotalVotes, "Total votes should not be nil")
		
		// Validate times submitted
		assert.Greater(t, attrs.TimesSubmitted, 0, "Times submitted should be greater than 0 for known URL")

		LogResponse(t, "URL: %s", attrs.URL)
		LogResponse(t, "Reputation: %d", attrs.Reputation)
		LogResponse(t, "Times Submitted: %d", attrs.TimesSubmitted)
		LogResponse(t, "Last Analysis Date: %d", attrs.LastAnalysisDate)
		LogResponse(t, "Analysis Stats - Malicious: %d, Suspicious: %d, Harmless: %d, Undetected: %d",
			attrs.LastAnalysisStats.Malicious,
			attrs.LastAnalysisStats.Suspicious,
			attrs.LastAnalysisStats.Harmless,
			attrs.LastAnalysisStats.Undetected)
		LogResponse(t, "Total Votes - Harmless: %d, Malicious: %d", attrs.TotalVotes.Harmless, attrs.TotalVotes.Malicious)
		
		// Log categories if present
		if len(attrs.Categories) > 0 {
			LogResponse(t, "Categories: %v", attrs.Categories)
		}
	})
}

// TestAcceptance_URLs_GetURLReport_InvalidURLID tests error handling for invalid URL ID
func TestAcceptance_URLs_GetURLReport_InvalidURLID(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := urls.NewService(Client)

		LogResponse(t, "Testing GetURLReport with invalid URL ID")

		// Use invalid URL ID (contains invalid characters)
		result, err := service.GetURLReport(ctx, "invalid@#$%url-id")

		// We expect an error for an invalid URL ID
		assert.Error(t, err, "GetURLReport should return an error for invalid URL ID")
		assert.Nil(t, result, "GetURLReport result should be nil for invalid URL ID")

		LogResponse(t, "Expected error received: %v", err)
	})
}

// TestAcceptance_URLs_GetURLReport_EmptyURLID tests validation for empty URL ID
func TestAcceptance_URLs_GetURLReport_EmptyURLID(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := urls.NewService(Client)

		LogResponse(t, "Testing GetURLReport with empty URL ID")

		result, err := service.GetURLReport(ctx, "")

		// Should fail validation
		assert.Error(t, err, "GetURLReport should return an error for empty URL ID")
		assert.Nil(t, result, "GetURLReport result should be nil for empty URL ID")
		assert.Contains(t, err.Error(), "URL ID cannot be empty", "Error should mention empty URL ID")

		LogResponse(t, "Validation error received as expected: %v", err)
	})
}

// TestAcceptance_URLs_GetCommentsOnURL tests retrieving comments on a URL
func TestAcceptance_URLs_GetCommentsOnURL(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := urls.NewService(Client)

		LogResponse(t, "Testing GetCommentsOnURL with URL ID: %s", Config.KnownURLID)

		// Get comments with limit
		opts := &urls.GetRelatedObjectsOptions{Limit: 10}
		result, err := service.GetCommentsOnURL(ctx, Config.KnownURLID, opts)
		AssertNoError(t, err, "GetCommentsOnURL should not return an error")
		AssertNotNil(t, result, "GetCommentsOnURL result should not be nil")

		// Validate response structure
		assert.NotNil(t, result.Data, "Comments data should not be nil")
		assert.IsType(t, []urls.RelatedObject{}, result.Data, "Data should be slice of RelatedObject")
		
		commentCount := len(result.Data)
		LogResponse(t, "Retrieved %d comments", commentCount)
		
		// If comments exist, validate first comment structure
		if commentCount > 0 {
			comment := result.Data[0]
			assert.NotEmpty(t, comment.ID, "Comment ID should not be empty")
			assert.Equal(t, "comment", comment.Type, "Comment type should be 'comment'")
		}
	})
}
