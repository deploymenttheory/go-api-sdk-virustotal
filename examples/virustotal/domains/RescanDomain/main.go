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

	apiKey := os.Getenv("VIRUSTOTAL_API_KEY")

	if apiKey == "" {
		log.Fatal("VIRUSTOTAL_API_KEY environment variable must be set")
	}

	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()

	vtClient, err := virustotal.NewClient(apiKey,
		client.WithLogger(logger),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Request a domain rescan
	ctx := context.Background()
	domain := "example.com" // Example domain

	result, err := vtClient.Domains.RescanDomain(ctx, domain)
	if err != nil {
		log.Fatalf("Failed to request domain rescan: %v", err)
	}

	// Print the rescan request information
	fmt.Printf("\n=== Domain Rescan Requested ===\n")
	fmt.Printf("Domain: %s\n", domain)
	fmt.Printf("Analysis ID: %s\n", result.Data.ID)
	fmt.Printf("Type: %s\n", result.Data.Type)
	fmt.Printf("Analysis URL: %s\n", result.Data.Links.Self)
	fmt.Printf("\nThe domain will be reanalyzed with the latest detection signatures\n")
	fmt.Printf("Use the analysis URL to check the status of the scan\n")

	logger.Info("Domain rescan requested successfully",
		zap.String("domain", domain),
		zap.String("analysis_id", result.Data.ID))
}
