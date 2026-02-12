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
		assert.Equal(t, Config.KnownAnalysisID, result.Data.ID, "Analysis ID should match requested ID")
		assert.NotNil(t, result.Data.Attributes, "Analysis attributes should not be nil")

		LogResponse(t, "Analysis Status: %s", result.Data.Attributes.Status)
		LogResponse(t, "Analysis Stats - Malicious: %d, Suspicious: %d, Harmless: %d",
			result.Data.Attributes.Stats.Malicious,
			result.Data.Attributes.Stats.Suspicious,
			result.Data.Attributes.Stats.Harmless)
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
