package acceptance

import (
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/files"
	"github.com/stretchr/testify/assert"
)

// TestAcceptance_Files_GetFileReport tests retrieving file information by hash
func TestAcceptance_Files_GetFileReport(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := files.NewService(Client)

		LogResponse(t, "Testing GetFileReport with hash: %s", Config.KnownFileHash)

		result, err := service.GetFileReport(ctx, Config.KnownFileHash)
		AssertNoError(t, err, "GetFileReport should not return an error")
		AssertNotNil(t, result, "GetFileReport result should not be nil")

		// Validate response structure
		assert.NotNil(t, result.Data, "File data should not be nil")
		assert.Equal(t, "file", result.Data.Type, "Response type should be 'file'")
		assert.NotNil(t, result.Data.Attributes, "File attributes should not be nil")

		// EICAR file should be detected as malicious by most engines
		assert.NotNil(t, result.Data.Attributes.LastAnalysisStats, "Analysis stats should not be nil")

		LogResponse(t, "File analysis stats - Malicious: %d, Suspicious: %d, Harmless: %d, Undetected: %d",
			result.Data.Attributes.LastAnalysisStats.Malicious,
			result.Data.Attributes.LastAnalysisStats.Suspicious,
			result.Data.Attributes.LastAnalysisStats.Harmless,
			result.Data.Attributes.LastAnalysisStats.Undetected)
	})
}

// TestAcceptance_Files_GetFileReport_InvalidHash tests error handling
func TestAcceptance_Files_GetFileReport_InvalidHash(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := files.NewService(Client)

		LogResponse(t, "Testing GetFileReport with invalid hash")

		// Use a non-existent hash
		result, err := service.GetFileReport(ctx, "0000000000000000000000000000000000000000000000000000000000000000")

		// We expect an error (404 Not Found)
		assert.Error(t, err, "GetFileReport should return an error for non-existent hash")
		assert.Nil(t, result, "GetFileReport result should be nil for non-existent hash")

		LogResponse(t, "Expected error received: %v", err)
	})
}

// TestAcceptance_Files_GetFileReport_EmptyHash tests validation
func TestAcceptance_Files_GetFileReport_EmptyHash(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := files.NewService(Client)

		LogResponse(t, "Testing GetFileReport with empty hash")

		result, err := service.GetFileReport(ctx, "")

		// Should fail validation
		assert.Error(t, err, "GetFileReport should return an error for empty hash")
		assert.Nil(t, result, "GetFileReport result should be nil for empty hash")
		assert.Contains(t, err.Error(), "file hash is required", "Error should mention required hash")

		LogResponse(t, "Validation error received as expected: %v", err)
	})
}
