package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"go.uber.org/zap"
)

func main() {

	apiKey := os.Getenv("VT_API_KEY")

	if apiKey == "" {
		log.Fatal("VT_API_KEY environment variable is required")
	}

	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()

	vtClient, err := virustotal.NewClientFromEnv(
		client.WithLogger(logger),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	domain := "example.com" // Example domain

	// Supported relationships: communicating_files, downloaded_files, historical_ssl_certificates,
	// historical_whois, subdomains, resolutions, comments, and more
	relationship := "resolutions"

	// Default behavior: Pass nil to automatically fetch all pages
	fmt.Println("=== Get All Related Objects (Automatic Pagination) ===")
	fmt.Printf("Fetching all %s for domain: %s\n\n", relationship, domain)

	response, _, err := vtClient.Domains.GetObjectsRelatedToDomain(ctx, domain, relationship, nil)
	if err != nil {
		log.Fatalf("Failed to get related objects: %v", err)
	}

	fmt.Printf("Total objects retrieved: %d\n\n", len(response.Data))

	if len(response.Data) == 0 {
		fmt.Printf("No %s found for this domain\n", relationship)
		return
	}

	// Display first 10 objects
	displayCount := 10
	if len(response.Data) < displayCount {
		displayCount = len(response.Data)
	}

	for i := 0; i < displayCount; i++ {
		obj := response.Data[i]
		fmt.Printf("%d. Type: %s\n", i+1, obj.Type)
		fmt.Printf("   ID: %s\n", obj.ID)
		if len(obj.Attributes) > 0 {
			// For resolutions, show IP address
			if ipAddress, ok := obj.Attributes["ip_address"].(string); ok {
				fmt.Printf("   IP Address: %s\n", ipAddress)
			}
			// Show date if available
			if date, ok := obj.Attributes["date"].(float64); ok {
				fmt.Printf("   Date: %d\n", int64(date))
			}
		}
		fmt.Println()
	}

	if len(response.Data) > displayCount {
		fmt.Printf("... and %d more objects\n", len(response.Data)-displayCount)
	}

	logger.Info("Related objects retrieved successfully",
		zap.String("domain", domain),
		zap.String("relationship", relationship),
		zap.Int("object_count", len(response.Data)))
}
