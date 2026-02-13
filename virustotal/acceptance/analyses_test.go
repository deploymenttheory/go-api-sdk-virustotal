package acceptance

import (
	"testing"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/analyses"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/urls"
	"github.com/stretchr/testify/assert"
)

// TestAcceptance_Analyses_GetAnalysis tests retrieving an analysis by ID
func TestAcceptance_Analyses_GetAnalysis(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := analyses.NewService(Client)

		LogTestStage(t, "🔍 API Call", "Testing GetAnalysis with ID: %s", Config.KnownAnalysisID)

		result, resp, err := service.GetAnalysis(ctx, Config.KnownAnalysisID)
		AssertNoError(t, err, "GetAnalysis should not return an error")
		AssertNotNil(t, result, "GetAnalysis result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")
		assert.NotNil(t, resp.Headers, "Response headers should not be nil")

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

		LogTestSuccess(t, "Analysis Status: %s, Malicious: %d, Suspicious: %d, Harmless: %d, Undetected: %d, Timeout: %d",
			attrs.Status,
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

		LogTestStage(t, "❌ Error Test", "Testing GetAnalysis with invalid ID")

		result, resp, err := service.GetAnalysis(ctx, "invalid-analysis-id-12345")

		// We expect an error for an invalid ID
		assert.Error(t, err, "GetAnalysis should return an error for invalid ID")
		assert.Nil(t, result, "GetAnalysis result should be nil for invalid ID")
		assert.NotNil(t, resp, "Response should not be nil for API errors")
		assert.NotEqual(t, 200, resp.StatusCode, "Status code should not be 200 for invalid ID")

		LogTestSuccess(t, "Expected error received: %v", err)
	})
}

// TestAcceptance_Analyses_GetAnalysis_EmptyID tests validation for empty analysis ID
func TestAcceptance_Analyses_GetAnalysis_EmptyID(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := analyses.NewService(Client)

		LogTestStage(t, "🔒 Validation", "Testing GetAnalysis with empty ID")

		result, resp, err := service.GetAnalysis(ctx, "")

		// Should fail validation
		assert.Error(t, err, "GetAnalysis should return an error for empty ID")
		assert.Nil(t, result, "GetAnalysis result should be nil for empty ID")
		assert.Nil(t, resp, "Response should be nil for validation errors (no HTTP call made)")
		assert.Contains(t, err.Error(), "analysis ID is required", "Error should mention required ID")

		LogTestSuccess(t, "Validation error received as expected: %v", err)
	})
}

// TestAcceptance_Analyses_GetObjectsRelatedToAnalysis tests retrieving related objects (item relationship)
func TestAcceptance_Analyses_GetObjectsRelatedToAnalysis(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := analyses.NewService(Client)

		LogTestStage(t, "🔗 Relationships", "Testing GetObjectsRelatedToAnalysis (item) with analysis ID: %s", Config.KnownAnalysisID)

		// Get related item (file or URL that was analyzed)
		opts := &analyses.GetRelatedObjectsOptions{Limit: 10}
		result, resp, err := service.GetObjectsRelatedToAnalysis(ctx, Config.KnownAnalysisID, "item", opts)
		AssertNoError(t, err, "GetObjectsRelatedToAnalysis should not return an error")
		AssertNotNil(t, result, "GetObjectsRelatedToAnalysis result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Related objects data should not be nil")
		assert.IsType(t, []analyses.RelatedObject{}, result.Data, "Data should be slice of RelatedObject")

		objectCount := len(result.Data)
		LogTestSuccess(t, "Retrieved %d related objects", objectCount)

		// Should have at least one item (the analyzed file/URL)
		if objectCount > 0 {
			item := result.Data[0]
			assert.NotEmpty(t, item.ID, "Item ID should not be empty")
			assert.NotEmpty(t, item.Type, "Item type should not be empty")
			assert.Contains(t, []string{"file", "url"}, item.Type, "Item type should be file or url")

			t.Logf("  Related item - Type: %s, ID: %s", item.Type, item.ID)
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

		LogTestStage(t, "🔗 Relationships", "Testing GetObjectDescriptorsRelatedToAnalysis (item) with analysis ID: %s", Config.KnownAnalysisID)

		// Get related item descriptors (lightweight IDs only)
		opts := &analyses.GetRelatedObjectsOptions{Limit: 10}
		result, resp, err := service.GetObjectDescriptorsRelatedToAnalysis(ctx, Config.KnownAnalysisID, "item", opts)
		AssertNoError(t, err, "GetObjectDescriptorsRelatedToAnalysis should not return an error")
		AssertNotNil(t, result, "GetObjectDescriptorsRelatedToAnalysis result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Related descriptors data should not be nil")
		assert.IsType(t, []analyses.ObjectDescriptor{}, result.Data, "Data should be slice of ObjectDescriptor")

		descriptorCount := len(result.Data)
		LogTestSuccess(t, "Retrieved %d object descriptors", descriptorCount)

		// Should have at least one descriptor
		if descriptorCount > 0 {
			descriptor := result.Data[0]
			assert.NotEmpty(t, descriptor.ID, "Descriptor ID should not be empty")
			assert.NotEmpty(t, descriptor.Type, "Descriptor type should not be empty")

			t.Logf("  Related descriptor - Type: %s, ID: %s", descriptor.Type, descriptor.ID)
		}
	})
}

// TestAcceptance_Analyses_GetSubmission tests retrieving a submission object
func TestAcceptance_Analyses_GetSubmission(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		analysesService := analyses.NewService(Client)
		urlsService := urls.NewService(Client)

		// First, scan a URL to get a fresh submission/analysis ID
		testURL := "http://www.example.com"
		LogTestStage(t, "🌐 URL Scan", "Scanning URL to obtain submission ID: %s", testURL)

		scanResult, scanResp, scanErr := urlsService.ScanURL(ctx, testURL)
		AssertNoError(t, scanErr, "ScanURL should not return an error")
		AssertNotNil(t, scanResult, "ScanURL result should not be nil")
		AssertNotNil(t, scanResp, "ScanURL response should not be nil")
		assert.Equal(t, 200, scanResp.StatusCode, "ScanURL status code should be 200")

		submissionID := scanResult.Data.ID
		assert.NotEmpty(t, submissionID, "Submission ID should not be empty")
		LogTestSuccess(t, "Obtained submission ID: %s", submissionID)

		// Now test GetSubmission with the fresh ID
		LogTestStage(t, "🔍 API Call", "Testing GetSubmission with submission ID: %s", submissionID)

		result, resp, err := analysesService.GetSubmission(ctx, submissionID)
		AssertNoError(t, err, "GetSubmission should not return an error")
		AssertNotNil(t, result, "GetSubmission result should not be nil")
		AssertNotNil(t, resp, "Response should not be nil")
		assert.Equal(t, 200, resp.StatusCode, "Status code should be 200")

		// Validate response structure
		assert.NotNil(t, result.Data, "Submission data should not be nil")
		assert.Equal(t, "submission", result.Data.Type, "Response type should be 'submission'")
		assert.NotEmpty(t, result.Data.ID, "Submission ID should not be empty")
		assert.NotNil(t, result.Data.Attributes, "Submission attributes should not be nil")

		// Validate submission attributes
		attrs := result.Data.Attributes
		assert.Greater(t, attrs.Date, int64(0), "Submission date should be valid timestamp")

		LogTestSuccess(t, "Submission ID: %s, Date: %d", result.Data.ID, attrs.Date)
		
		// Premium API fields (may be empty for free tier)
		if attrs.Interface != "" {
			t.Logf("  Submission Interface: %s", attrs.Interface)
		}
		if attrs.Country != "" {
			t.Logf("  Submission Country: %s", attrs.Country)
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

		LogTestStage(t, "🔒 Validation", "Testing GetSubmission with empty ID")

		result, resp, err := service.GetSubmission(ctx, "")

		// Should fail validation
		assert.Error(t, err, "GetSubmission should return an error for empty ID")
		assert.Nil(t, result, "GetSubmission result should be nil for empty ID")
		assert.Nil(t, resp, "Response should be nil for validation errors (no HTTP call made)")
		assert.Contains(t, err.Error(), "submission ID is required", "Error should mention required submission ID")

		LogTestSuccess(t, "Validation error received as expected: %v", err)
	})
}
