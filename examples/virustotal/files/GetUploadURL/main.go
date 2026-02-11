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

	// Get upload URL for large files (>32MB)
	ctx := context.Background()

	result, err := vtClient.Files.GetUploadURL(ctx)
	if err != nil {
		log.Fatalf("Failed to get upload URL: %v", err)
	}

	// Print the upload URL
	fmt.Printf("\n=== Upload URL for Large Files ===\n")
	fmt.Printf("URL: %s\n", result.Data)
	fmt.Printf("\nUse this URL to upload files larger than 32MB\n")
	fmt.Printf("The URL is valid for a limited time\n")

	logger.Info("Upload URL retrieved successfully",
		zap.String("url", result.Data))
}
