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
