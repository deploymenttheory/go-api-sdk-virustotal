package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"go.uber.org/zap"
)

// This example demonstrates creating a production-ready client with custom configuration.
//
// Use this approach when:
// - Running in production environments
// - You need structured logging
// - You want to customize timeouts and retries
// - You need to add custom headers
// - You want fine-grained control over client behavior
//
// This example shows:
// - Structured logging with zap
// - Custom timeout configuration
// - Retry policy tuning
// - Custom headers for request tracking
// - Debug mode for development

func main() {
	// Check API key from environment
	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		log.Fatal("VT_API_KEY environment variable is required")
	}

	// Step 1: Create a structured logger
	// Use NewProduction() for production, NewDevelopment() for local dev
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()

	// Step 2: Create client with custom configuration
	vtClient, err := virustotal.NewClientFromEnv(
		// Structured logging for production observability
		client.WithLogger(logger),

		// Custom timeout for slow networks or large file operations
		client.WithTimeout(60*time.Second),

		// Retry configuration for better reliability
		client.WithRetryCount(5),                       // Retry up to 5 times
		client.WithRetryWaitTime(3*time.Second),        // Initial wait time
		client.WithRetryMaxWaitTime(30*time.Second),    // Maximum wait time

		// Add custom headers for request tracking
		client.WithGlobalHeader("X-Application-Name", "MySecurityApp"),
		client.WithGlobalHeader("X-Application-Version", "1.0.0"),
		client.WithGlobalHeader("X-Environment", "production"),

		// Uncomment to enable debug mode (only for development!)
		// client.WithDebug(),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	logger.Info("VirusTotal client created",
		zap.String("timeout", "60s"),
		zap.Int("retry_count", 5))

	// Step 3: Use the client with structured logging
	ctx := context.Background()
	ipAddress := "8.8.8.8"

	logger.Info("Fetching IP address report",
		zap.String("ip_address", ipAddress))

	report, resp, err := vtClient.IPAddresses.GetIPAddressReport(ctx, ipAddress)
	if err != nil {
		logger.Error("Failed to get IP report",
			zap.String("ip_address", ipAddress),
			zap.Error(err),
			zap.Int("status_code", resp.StatusCode))
		log.Fatalf("API call failed: %v", err)
	}

	// Log successful operation
	logger.Info("IP address report retrieved",
		zap.String("ip_address", ipAddress),
		zap.Int("status_code", resp.StatusCode),
		zap.Duration("duration", resp.Duration),
		zap.Int64("response_size", resp.Size),
		zap.Int("malicious_detections", report.Data.Attributes.LastAnalysisStats.Malicious))

	// Display results
	fmt.Printf("\n✓ Production-ready client created successfully\n\n")
	fmt.Printf("Configuration:\n")
	fmt.Printf("  Timeout: 60s\n")
	fmt.Printf("  Retry Count: 5\n")
	fmt.Printf("  Logger: zap (production)\n")
	fmt.Printf("  Custom Headers: 3\n")

	fmt.Printf("\nIP Address Report:\n")
	fmt.Printf("  IP: %s\n", report.Data.ID)
	fmt.Printf("  Country: %s\n", report.Data.Attributes.Country)
	fmt.Printf("  ASN: %d\n", report.Data.Attributes.ASN)
	fmt.Printf("  Network: %s\n", report.Data.Attributes.Network)

	fmt.Printf("\nAPI Response:\n")
	fmt.Printf("  Status Code: %d\n", resp.StatusCode)
	fmt.Printf("  Duration: %v\n", resp.Duration)
	fmt.Printf("  Response Size: %d bytes\n", resp.Size)

	fmt.Printf("\nDetection Stats:\n")
	fmt.Printf("  Malicious: %d\n", report.Data.Attributes.LastAnalysisStats.Malicious)
	fmt.Printf("  Suspicious: %d\n", report.Data.Attributes.LastAnalysisStats.Suspicious)
	fmt.Printf("  Harmless: %d\n", report.Data.Attributes.LastAnalysisStats.Harmless)

	fmt.Printf("\n✓ Custom client with logging example completed successfully!\n")
}
