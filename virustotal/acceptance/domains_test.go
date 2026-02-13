package acceptance

import (
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/domains"
	"github.com/stretchr/testify/assert"
)

// TestAcceptance_Domains_GetDomainReport tests retrieving domain information
func TestAcceptance_Domains_GetDomainReport(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := domains.NewService(Client)

		LogResponse(t, "Testing GetDomainReport with domain: %s", Config.KnownDomain)

		result, resp, err := service.GetDomainReport(ctx, Config.KnownDomain)
		AssertNoError(t, err, "GetDomainReport should not return an error")
		AssertNotNil(t, result, "GetDomainReport result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")
		assert.NotNil(t, resp.Headers, "Response headers should not be nil")

		// Validate response structure
		assert.NotNil(t, result.Data, "Domain data should not be nil")
		assert.Equal(t, "domain", result.Data.Type, "Response type should be 'domain'")
		assert.Equal(t, Config.KnownDomain, result.Data.ID, "Domain ID should match requested domain")
		assert.NotNil(t, result.Data.Attributes, "Domain attributes should not be nil")

		// Validate domain attributes
		attrs := result.Data.Attributes
		assert.NotNil(t, attrs.LastAnalysisStats, "Last analysis stats should not be nil")
		assert.GreaterOrEqual(t, attrs.LastAnalysisStats.Harmless, 0, "Harmless count should be >= 0")
		assert.GreaterOrEqual(t, attrs.LastAnalysisStats.Malicious, 0, "Malicious count should be >= 0")
		assert.GreaterOrEqual(t, attrs.LastAnalysisStats.Suspicious, 0, "Suspicious count should be >= 0")
		assert.GreaterOrEqual(t, attrs.LastAnalysisStats.Undetected, 0, "Undetected count should be >= 0")
		
		// Validate timestamp fields
		assert.Greater(t, attrs.LastAnalysisDate, int64(0), "Last analysis date should be valid")
		assert.Greater(t, attrs.LastModificationDate, int64(0), "Last modification date should be valid")
		
		// Validate reputation
		assert.NotEqual(t, 0, attrs.Reputation, "Reputation should be set")
		
		// For google.com, expect categories to be populated
		if Config.KnownDomain == "google.com" {
			assert.NotEmpty(t, attrs.Categories, "Categories should not be empty for well-known domain")
		}

		LogResponse(t, "Domain: %s", Config.KnownDomain)
		LogResponse(t, "Reputation: %d", attrs.Reputation)
		LogResponse(t, "Last Analysis Date: %d", attrs.LastAnalysisDate)
		LogResponse(t, "Analysis Stats - Malicious: %d, Suspicious: %d, Harmless: %d, Undetected: %d",
			attrs.LastAnalysisStats.Malicious,
			attrs.LastAnalysisStats.Suspicious,
			attrs.LastAnalysisStats.Harmless,
			attrs.LastAnalysisStats.Undetected)
		
		if len(attrs.Categories) > 0 {
			LogResponse(t, "Categories: %v", attrs.Categories)
		}
	})
}

// TestAcceptance_Domains_GetDomainReport_InvalidDomain tests error handling
func TestAcceptance_Domains_GetDomainReport_InvalidDomain(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := domains.NewService(Client)

		LogResponse(t, "Testing GetDomainReport with invalid domain")

		// Use an intentionally malformed domain
		result, resp, err := service.GetDomainReport(ctx, "this-is-not-a-valid-domain-12345.invalid")

		// We expect an error for an invalid/unknown domain
		assert.Error(t, err, "GetDomainReport should return an error for invalid domain")
		assert.Nil(t, result, "GetDomainReport result should be nil for invalid domain")
		assert.Nil(t, resp, "Response should be nil for validation errors (no HTTP call made)")
		assert.NotEqual(t, 200, resp.StatusCode, "Status code should not be 200 for invalid domain")

		LogResponse(t, "Expected error received: %v", err)
	})
}

// TestAcceptance_Domains_GetDomainReport_EmptyDomain tests validation
func TestAcceptance_Domains_GetDomainReport_EmptyDomain(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := domains.NewService(Client)

		LogResponse(t, "Testing GetDomainReport with empty domain")

		result, resp, err := service.GetDomainReport(ctx, "")

		// Should fail validation
		assert.Error(t, err, "GetDomainReport should return an error for empty domain")
		assert.Nil(t, result, "GetDomainReport result should be nil for empty domain")
		assert.Nil(t, resp, "Response should be nil for validation errors (no HTTP call made)")
		assert.Contains(t, err.Error(), "domain is required", "Error should mention required domain")

		LogResponse(t, "Validation error received as expected: %v", err)
	})
}

// TestAcceptance_Domains_GetCommentsOnDomain tests retrieving comments on a domain
func TestAcceptance_Domains_GetCommentsOnDomain(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := domains.NewService(Client)

		LogResponse(t, "Testing GetCommentsOnDomain with domain: %s", Config.KnownDomain)

		// Get comments with limit
		opts := &domains.GetRelatedObjectsOptions{Limit: 10}
		result, resp, err := service.GetCommentsOnDomain(ctx, Config.KnownDomain, opts)
		AssertNoError(t, err, "GetCommentsOnDomain should not return an error")
		AssertNotNil(t, result, "GetCommentsOnDomain result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Comments data should not be nil")
		assert.IsType(t, []domains.RelatedObject{}, result.Data, "Data should be slice of RelatedObject")
		
		commentCount := len(result.Data)
		LogResponse(t, "Retrieved %d comments", commentCount)
		
		// If comments exist, validate first comment structure
		if commentCount > 0 {
			comment := result.Data[0]
			assert.NotEmpty(t, comment.ID, "Comment ID should not be empty")
			assert.Equal(t, "comment", comment.Type, "Comment type should be 'comment'")
			if comment.Attributes != nil {
				LogResponse(t, "First comment date: %v", comment.Attributes)
			}
		}
	})
}

// TestAcceptance_Domains_GetObjectsRelatedToDomain tests retrieving related objects (resolutions)
func TestAcceptance_Domains_GetObjectsRelatedToDomain(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := domains.NewService(Client)

		LogResponse(t, "Testing GetObjectsRelatedToDomain (resolutions) with domain: %s", Config.KnownDomain)

		// Get DNS resolutions with limit
		opts := &domains.GetRelatedObjectsOptions{Limit: 10}
		result, resp, err := service.GetObjectsRelatedToDomain(ctx, Config.KnownDomain, "resolutions", opts)
		AssertNoError(t, err, "GetObjectsRelatedToDomain should not return an error")
		AssertNotNil(t, result, "GetObjectsRelatedToDomain result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Resolutions data should not be nil")
		assert.IsType(t, []domains.RelatedObject{}, result.Data, "Data should be slice of RelatedObject")
		
		resolutionCount := len(result.Data)
		LogResponse(t, "Retrieved %d DNS resolutions", resolutionCount)
		
		// For google.com, expect DNS resolutions to exist
		if Config.KnownDomain == "google.com" {
			assert.Greater(t, resolutionCount, 0, "Well-known domain should have DNS resolutions")
			
			if resolutionCount > 0 {
				resolution := result.Data[0]
				assert.NotEmpty(t, resolution.ID, "Resolution ID should not be empty")
				assert.Equal(t, "resolution", resolution.Type, "Resolution type should be 'resolution'")
				LogResponse(t, "First resolution ID: %s", resolution.ID)
			}
		}
	})
}

// TestAcceptance_Domains_GetObjectDescriptorsRelatedToDomain tests retrieving related object descriptors
func TestAcceptance_Domains_GetObjectDescriptorsRelatedToDomain(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := domains.NewService(Client)

		LogResponse(t, "Testing GetObjectDescriptorsRelatedToDomain (resolutions) with domain: %s", Config.KnownDomain)

		// Get DNS resolution descriptors with limit
		opts := &domains.GetRelatedObjectsOptions{Limit: 10}
		result, resp, err := service.GetObjectDescriptorsRelatedToDomain(ctx, Config.KnownDomain, "resolutions", opts)
		AssertNoError(t, err, "GetObjectDescriptorsRelatedToDomain should not return an error")
		AssertNotNil(t, result, "GetObjectDescriptorsRelatedToDomain result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Descriptors data should not be nil")
		assert.IsType(t, []domains.ObjectDescriptor{}, result.Data, "Data should be slice of ObjectDescriptor")
		
		descriptorCount := len(result.Data)
		LogResponse(t, "Retrieved %d object descriptors", descriptorCount)
		
		// For google.com, expect descriptors to exist
		if Config.KnownDomain == "google.com" && descriptorCount > 0 {
			descriptor := result.Data[0]
			assert.NotEmpty(t, descriptor.ID, "Descriptor ID should not be empty")
			assert.Equal(t, "resolution", descriptor.Type, "Descriptor type should be 'resolution'")
			LogResponse(t, "First descriptor - Type: %s, ID: %s", descriptor.Type, descriptor.ID)
		}
	})
}

// TestAcceptance_Domains_GetVotesOnDomain tests retrieving votes on a domain
func TestAcceptance_Domains_GetVotesOnDomain(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := domains.NewService(Client)

		LogResponse(t, "Testing GetVotesOnDomain with domain: %s", Config.KnownDomain)

		// Get votes with limit
		opts := &domains.GetVotesOptions{Limit: 10}
		result, resp, err := service.GetVotesOnDomain(ctx, Config.KnownDomain, opts)
		AssertNoError(t, err, "GetVotesOnDomain should not return an error")
		AssertNotNil(t, result, "GetVotesOnDomain result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Votes data should not be nil")
		assert.IsType(t, []domains.Vote{}, result.Data, "Data should be slice of Vote")
		
		voteCount := len(result.Data)
		LogResponse(t, "Retrieved %d votes", voteCount)
		
		// If votes exist, validate structure
		if voteCount > 0 {
			vote := result.Data[0]
			assert.NotEmpty(t, vote.ID, "Vote ID should not be empty")
			assert.Equal(t, "vote", vote.Type, "Vote type should be 'vote'")
			assert.NotNil(t, vote.Attributes, "Vote attributes should not be nil")
			assert.Contains(t, []string{"harmless", "malicious"}, vote.Attributes.Verdict, "Verdict should be harmless or malicious")
			assert.Greater(t, vote.Attributes.Date, int64(0), "Vote date should be valid")
			
			LogResponse(t, "First vote - Verdict: %s, Date: %d", vote.Attributes.Verdict, vote.Attributes.Date)
		}
	})
}
