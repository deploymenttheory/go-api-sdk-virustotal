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
		assert.NotEmpty(t, result.Data.ID, "File ID should not be empty")
		assert.NotNil(t, result.Data.Attributes, "File attributes should not be nil")

		// Validate file attributes
		attrs := result.Data.Attributes
		assert.NotEmpty(t, attrs.MD5, "MD5 hash should not be empty")
		assert.NotEmpty(t, attrs.SHA1, "SHA1 hash should not be empty")
		assert.NotEmpty(t, attrs.SHA256, "SHA256 hash should not be empty")
		assert.Greater(t, attrs.Size, int64(0), "File size should be greater than 0")
		
		// EICAR file should be detected as malicious by most engines
		assert.NotNil(t, attrs.LastAnalysisStats, "Analysis stats should not be nil")
		assert.Greater(t, attrs.LastAnalysisStats.Malicious, 0, "EICAR file should be detected as malicious")
		assert.GreaterOrEqual(t, attrs.LastAnalysisStats.Harmless, 0, "Harmless count should be >= 0")
		assert.GreaterOrEqual(t, attrs.LastAnalysisStats.Suspicious, 0, "Suspicious count should be >= 0")
		assert.GreaterOrEqual(t, attrs.LastAnalysisStats.Undetected, 0, "Undetected count should be >= 0")
		
		// Validate timestamps
		assert.Greater(t, attrs.LastAnalysisDate, int64(0), "Last analysis date should be valid")
		assert.Greater(t, attrs.FirstSubmissionDate, int64(0), "First submission date should be valid")
		
		// Validate reputation and vote counts
		assert.NotNil(t, attrs.TotalVotes, "Total votes should not be nil")

		LogResponse(t, "File Hashes - MD5: %s, SHA1: %s, SHA256: %s", attrs.MD5, attrs.SHA1, attrs.SHA256)
		LogResponse(t, "File Size: %d bytes", attrs.Size)
		LogResponse(t, "Last Analysis Date: %d", attrs.LastAnalysisDate)
		LogResponse(t, "Analysis Stats - Malicious: %d, Suspicious: %d, Harmless: %d, Undetected: %d",
			attrs.LastAnalysisStats.Malicious,
			attrs.LastAnalysisStats.Suspicious,
			attrs.LastAnalysisStats.Harmless,
			attrs.LastAnalysisStats.Undetected)
		LogResponse(t, "Total Votes - Harmless: %d, Malicious: %d", attrs.TotalVotes.Harmless, attrs.TotalVotes.Malicious)
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
		assert.Contains(t, err.Error(), "file ID is required", "Error should mention required file ID")

		LogResponse(t, "Validation error received as expected: %v", err)
	})
}

// TestAcceptance_Files_GetUploadURL tests retrieving a file upload URL
func TestAcceptance_Files_GetUploadURL(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := files.NewService(Client)

		LogResponse(t, "Testing GetUploadURL")

		result, err := service.GetUploadURL(ctx)
		AssertNoError(t, err, "GetUploadURL should not return an error")
		AssertNotNil(t, result, "GetUploadURL result should not be nil")

		// Validate upload URL
		assert.NotEmpty(t, result.Data, "Upload URL should not be empty")
		assert.Contains(t, result.Data, "https://", "Upload URL should be HTTPS")
		assert.Contains(t, result.Data, "virustotal.com", "Upload URL should be VirusTotal domain")

		LogResponse(t, "Upload URL retrieved successfully: %s", result.Data)
	})
}

// TestAcceptance_Files_GetFileDownloadURL tests retrieving a file download URL
func TestAcceptance_Files_GetFileDownloadURL(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := files.NewService(Client)

		LogResponse(t, "Testing GetFileDownloadURL with hash: %s", Config.KnownFileHash)

		result, err := service.GetFileDownloadURL(ctx, Config.KnownFileHash)
		AssertNoError(t, err, "GetFileDownloadURL should not return an error")
		AssertNotNil(t, result, "GetFileDownloadURL result should not be nil")

		// Validate download URL
		assert.NotEmpty(t, result.Data, "Download URL should not be empty")
		assert.Contains(t, result.Data, "https://", "Download URL should be HTTPS")

		LogResponse(t, "Download URL retrieved successfully")
	})
}
