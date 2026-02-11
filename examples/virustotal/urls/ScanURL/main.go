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

	ctx := context.Background()
	url := "https://www.example.com" // URL to scan

	result, err := vtClient.URLs.ScanURL(ctx, url)
	if err != nil {
		log.Fatalf("Failed to scan URL: %v", err)
	}

	fmt.Printf("\n=== URL Scan Submitted ===\n")
	fmt.Printf("Analysis ID: %s\n", result.Data.ID)
	fmt.Printf("Type: %s\n", result.Data.Type)
	fmt.Printf("Self Link: %s\n\n", result.Data.Links.Self)

	fmt.Printf("You can use this analysis ID to retrieve scan results from the Analyses endpoint.\n")

	logger.Info("URL scan submitted successfully",
		zap.String("url", url),
		zap.String("analysis_id", result.Data.ID))
}
