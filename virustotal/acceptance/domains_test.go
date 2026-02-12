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

		result, err := service.GetDomainReport(ctx, Config.KnownDomain)
		AssertNoError(t, err, "GetDomainReport should not return an error")
		AssertNotNil(t, result, "GetDomainReport result should not be nil")

		// Validate response structure
		assert.NotNil(t, result.Data, "Domain data should not be nil")
		assert.Equal(t, "domain", result.Data.Type, "Response type should be 'domain'")
		assert.Equal(t, Config.KnownDomain, result.Data.ID, "Domain ID should match requested domain")
		assert.NotNil(t, result.Data.Attributes, "Domain attributes should not be nil")

		LogResponse(t, "Domain reputation: Malicious: %d, Suspicious: %d, Harmless: %d",
			result.Data.Attributes.LastAnalysisStats.Malicious,
			result.Data.Attributes.LastAnalysisStats.Suspicious,
			result.Data.Attributes.LastAnalysisStats.Harmless)
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
		result, err := service.GetDomainReport(ctx, "this-is-not-a-valid-domain-12345.invalid")

		// We expect an error for an invalid/unknown domain
		assert.Error(t, err, "GetDomainReport should return an error for invalid domain")
		assert.Nil(t, result, "GetDomainReport result should be nil for invalid domain")

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

		result, err := service.GetDomainReport(ctx, "")

		// Should fail validation
		assert.Error(t, err, "GetDomainReport should return an error for empty domain")
		assert.Nil(t, result, "GetDomainReport result should be nil for empty domain")
		assert.Contains(t, err.Error(), "domain is required", "Error should mention required domain")

		LogResponse(t, "Validation error received as expected: %v", err)
	})
}
