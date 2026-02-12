package acceptance

import (
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/analyses"
	"github.com/stretchr/testify/assert"
)

// TestAcceptance_Analyses_GetAnalysis tests retrieving an analysis by ID
func TestAcceptance_Analyses_GetAnalysis(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := analyses.NewService(Client)

		LogResponse(t, "Testing GetAnalysis with ID: %s", Config.KnownAnalysisID)

		result, err := service.GetAnalysis(ctx, Config.KnownAnalysisID)
		AssertNoError(t, err, "GetAnalysis should not return an error")
		AssertNotNil(t, result, "GetAnalysis result should not be nil")

		// Validate response structure
		assert.NotNil(t, result.Data, "Analysis data should not be nil")
		assert.Equal(t, "analysis", result.Data.Type, "Response type should be 'analysis'")
		assert.NotEmpty(t, result.Data.ID, "Analysis ID should not be empty")
		assert.NotNil(t, result.Data.Attributes, "Analysis attributes should not be nil")

		// Validate analysis attributes
		attrs := result.Data.Attributes
		assert.NotEmpty(t, attrs.Status, "Analysis status should not be empty")
		assert.Contains(t, []string{"queued", "in-progress", "completed"}, attrs.Status, "Status should be valid")
		
		// Validate stats structure
		assert.NotNil(t, attrs.Stats, "Analysis stats should not be nil")
		assert.GreaterOrEqual(t, attrs.Stats.Harmless, 0, "Harmless count should be >= 0")
		assert.GreaterOrEqual(t, attrs.Stats.Malicious, 0, "Malicious count should be >= 0")
		assert.GreaterOrEqual(t, attrs.Stats.Suspicious, 0, "Suspicious count should be >= 0")
		assert.GreaterOrEqual(t, attrs.Stats.Undetected, 0, "Undetected count should be >= 0")
		assert.GreaterOrEqual(t, attrs.Stats.Timeout, 0, "Timeout count should be >= 0")
		
		// Validate date field
		assert.Greater(t, attrs.Date, int64(0), "Analysis date should be a valid timestamp")

		LogResponse(t, "Analysis Status: %s", attrs.Status)
		LogResponse(t, "Analysis Date: %d", attrs.Date)
		LogResponse(t, "Analysis Stats - Malicious: %d, Suspicious: %d, Harmless: %d, Undetected: %d, Timeout: %d",
			attrs.Stats.Malicious,
			attrs.Stats.Suspicious,
			attrs.Stats.Harmless,
			attrs.Stats.Undetected,
			attrs.Stats.Timeout)
	})
}

// TestAcceptance_Analyses_GetAnalysis_InvalidID tests error handling for invalid analysis ID
func TestAcceptance_Analyses_GetAnalysis_InvalidID(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := analyses.NewService(Client)

		LogResponse(t, "Testing GetAnalysis with invalid ID")

		result, err := service.GetAnalysis(ctx, "invalid-analysis-id-12345")

		// We expect an error for an invalid ID
		assert.Error(t, err, "GetAnalysis should return an error for invalid ID")
		assert.Nil(t, result, "GetAnalysis result should be nil for invalid ID")

		LogResponse(t, "Expected error received: %v", err)
	})
}

// TestAcceptance_Analyses_GetAnalysis_EmptyID tests validation for empty analysis ID
func TestAcceptance_Analyses_GetAnalysis_EmptyID(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := analyses.NewService(Client)

		LogResponse(t, "Testing GetAnalysis with empty ID")

		result, err := service.GetAnalysis(ctx, "")

		// Should fail validation
		assert.Error(t, err, "GetAnalysis should return an error for empty ID")
		assert.Nil(t, result, "GetAnalysis result should be nil for empty ID")
		assert.Contains(t, err.Error(), "analysis ID is required", "Error should mention required ID")

		LogResponse(t, "Validation error received as expected: %v", err)
	})
}

// TestAcceptance_Analyses_GetObjectsRelatedToAnalysis tests retrieving related objects (item relationship)
func TestAcceptance_Analyses_GetObjectsRelatedToAnalysis(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := analyses.NewService(Client)

		LogResponse(t, "Testing GetObjectsRelatedToAnalysis (item) with analysis ID: %s", Config.KnownAnalysisID)

		// Get related item (file or URL that was analyzed)
		opts := &analyses.GetRelatedObjectsOptions{Limit: 10}
		result, err := service.GetObjectsRelatedToAnalysis(ctx, Config.KnownAnalysisID, "item", opts)
		AssertNoError(t, err, "GetObjectsRelatedToAnalysis should not return an error")
		AssertNotNil(t, result, "GetObjectsRelatedToAnalysis result should not be nil")

		// Validate response structure
		assert.NotNil(t, result.Data, "Related objects data should not be nil")
		assert.IsType(t, []analyses.RelatedObject{}, result.Data, "Data should be slice of RelatedObject")
		
		objectCount := len(result.Data)
		LogResponse(t, "Retrieved %d related objects", objectCount)
		
		// Should have at least one item (the analyzed file/URL)
		if objectCount > 0 {
			item := result.Data[0]
			assert.NotEmpty(t, item.ID, "Item ID should not be empty")
			assert.NotEmpty(t, item.Type, "Item type should not be empty")
			assert.Contains(t, []string{"file", "url"}, item.Type, "Item type should be file or url")
			
			LogResponse(t, "Related item - Type: %s, ID: %s", item.Type, item.ID)
		}
	})
}

// TestAcceptance_Analyses_GetObjectDescriptorsRelatedToAnalysis tests retrieving related object descriptors
func TestAcceptance_Analyses_GetObjectDescriptorsRelatedToAnalysis(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := analyses.NewService(Client)

		LogResponse(t, "Testing GetObjectDescriptorsRelatedToAnalysis (item) with analysis ID: %s", Config.KnownAnalysisID)

		// Get related item descriptors (lightweight IDs only)
		opts := &analyses.GetRelatedObjectsOptions{Limit: 10}
		result, err := service.GetObjectDescriptorsRelatedToAnalysis(ctx, Config.KnownAnalysisID, "item", opts)
		AssertNoError(t, err, "GetObjectDescriptorsRelatedToAnalysis should not return an error")
		AssertNotNil(t, result, "GetObjectDescriptorsRelatedToAnalysis result should not be nil")

		// Validate response structure
		assert.NotNil(t, result.Data, "Related descriptors data should not be nil")
		assert.IsType(t, []analyses.ObjectDescriptor{}, result.Data, "Data should be slice of ObjectDescriptor")
		
		descriptorCount := len(result.Data)
		LogResponse(t, "Retrieved %d object descriptors", descriptorCount)
		
		// Should have at least one descriptor
		if descriptorCount > 0 {
			descriptor := result.Data[0]
			assert.NotEmpty(t, descriptor.ID, "Descriptor ID should not be empty")
			assert.NotEmpty(t, descriptor.Type, "Descriptor type should not be empty")
			
			LogResponse(t, "Related descriptor - Type: %s, ID: %s", descriptor.Type, descriptor.ID)
		}
	})
}

// TestAcceptance_Analyses_GetSubmission tests retrieving a submission object
func TestAcceptance_Analyses_GetSubmission(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := analyses.NewService(Client)

		// Use analysis ID as submission ID (they share same ID space)
		submissionID := Config.KnownAnalysisID
		LogResponse(t, "Testing GetSubmission with submission ID: %s", submissionID)

		result, err := service.GetSubmission(ctx, submissionID)
		AssertNoError(t, err, "GetSubmission should not return an error")
		AssertNotNil(t, result, "GetSubmission result should not be nil")

		// Validate response structure
		assert.NotNil(t, result.Data, "Submission data should not be nil")
		assert.Equal(t, "submission", result.Data.Type, "Response type should be 'submission'")
		assert.NotEmpty(t, result.Data.ID, "Submission ID should not be empty")
		assert.NotNil(t, result.Data.Attributes, "Submission attributes should not be nil")

		// Validate submission attributes
		attrs := result.Data.Attributes
		assert.Greater(t, attrs.Date, int64(0), "Submission date should be valid timestamp")

		LogResponse(t, "Submission ID: %s", result.Data.ID)
		LogResponse(t, "Submission Date: %d", attrs.Date)
		
		// Premium API fields (may be empty for free tier)
		if attrs.Interface != "" {
			LogResponse(t, "Submission Interface: %s", attrs.Interface)
		}
		if attrs.Country != "" {
			LogResponse(t, "Submission Country: %s", attrs.Country)
		}
	})
}

// TestAcceptance_Analyses_GetSubmission_EmptyID tests validation for empty submission ID
func TestAcceptance_Analyses_GetSubmission_EmptyID(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := analyses.NewService(Client)

		LogResponse(t, "Testing GetSubmission with empty ID")

		result, err := service.GetSubmission(ctx, "")

		// Should fail validation
		assert.Error(t, err, "GetSubmission should return an error for empty ID")
		assert.Nil(t, result, "GetSubmission result should be nil for empty ID")
		assert.Contains(t, err.Error(), "submission ID is required", "Error should mention required submission ID")

		LogResponse(t, "Validation error received as expected: %v", err)
	})
}
