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
	// URL ID can be SHA-256 hash or base64-encoded URL without padding
	urlID := "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20"

	result, _, err := vtClient.URLs.RescanURL(ctx, urlID)
	if err != nil {
		log.Fatalf("Failed to rescan URL: %v", err)
	}

	fmt.Printf("\n=== URL Rescan Submitted ===\n")
	fmt.Printf("Analysis ID: %s\n", result.Data.ID)
	fmt.Printf("Type: %s\n\n", result.Data.Type)

	fmt.Printf("The URL has been queued for reanalysis.\n")
	fmt.Printf("Use this analysis ID to retrieve results from the Analyses endpoint.\n")

	logger.Info("URL rescan submitted successfully",
		zap.String("url_id", urlID),
		zap.String("analysis_id", result.Data.ID))
}
