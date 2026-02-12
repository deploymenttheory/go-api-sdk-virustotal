package acceptance

import (
	"testing"

	ipaddresses "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/ip_addresses"
	"github.com/stretchr/testify/assert"
)

// TestAcceptance_IPAddresses_GetIPAddressReport tests retrieving IP address information
func TestAcceptance_IPAddresses_GetIPAddressReport(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := ipaddresses.NewService(Client)

		LogResponse(t, "Testing GetIPAddressReport with IP: %s", Config.KnownIPAddress)

		result, err := service.GetIPAddressReport(ctx, Config.KnownIPAddress, nil)
		AssertNoError(t, err, "GetIPAddressReport should not return an error")
		AssertNotNil(t, result, "GetIPAddressReport result should not be nil")

		// Validate response structure
		assert.NotNil(t, result.Data, "IP address data should not be nil")
		assert.Equal(t, "ip_address", result.Data.Type, "Response type should be 'ip_address'")
		assert.Equal(t, Config.KnownIPAddress, result.Data.ID, "IP address should match requested IP")
		assert.NotNil(t, result.Data.Attributes, "IP address attributes should not be nil")

		LogResponse(t, "IP reputation: Malicious: %d, Suspicious: %d, Harmless: %d",
			result.Data.Attributes.LastAnalysisStats.Malicious,
			result.Data.Attributes.LastAnalysisStats.Suspicious,
			result.Data.Attributes.LastAnalysisStats.Harmless)

		// Google DNS (8.8.8.8) should have network and country info
		if result.Data.Attributes.Network != "" {
			LogResponse(t, "Network: %s", result.Data.Attributes.Network)
		}
		if result.Data.Attributes.Country != "" {
			LogResponse(t, "Country: %s", result.Data.Attributes.Country)
		}
	})
}

// TestAcceptance_IPAddresses_GetIPAddressReport_InvalidIP tests error handling
func TestAcceptance_IPAddresses_GetIPAddressReport_InvalidIP(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := ipaddresses.NewService(Client)

		LogResponse(t, "Testing GetIPAddressReport with invalid IP")

		// Use an invalid IP address format
		result, err := service.GetIPAddressReport(ctx, "999.999.999.999", nil)

		// We expect an error for an invalid IP
		assert.Error(t, err, "GetIPAddressReport should return an error for invalid IP")
		assert.Nil(t, result, "GetIPAddressReport result should be nil for invalid IP")

		LogResponse(t, "Expected error received: %v", err)
	})
}

// TestAcceptance_IPAddresses_GetIPAddressReport_EmptyIP tests validation
func TestAcceptance_IPAddresses_GetIPAddressReport_EmptyIP(t *testing.T) {
	RequireClient(t)

	RateLimitedTest(t, func(t *testing.T) {
		ctx, cancel := NewContext()
		defer cancel()

		service := ipaddresses.NewService(Client)

		LogResponse(t, "Testing GetIPAddressReport with empty IP")

		result, err := service.GetIPAddressReport(ctx, "", nil)

		// Should fail validation
		assert.Error(t, err, "GetIPAddressReport should return an error for empty IP")
		assert.Nil(t, result, "GetIPAddressReport result should be nil for empty IP")
		assert.Contains(t, err.Error(), "IP address is required", "Error should mention required IP")

		LogResponse(t, "Validation error received as expected: %v", err)
	})
}
