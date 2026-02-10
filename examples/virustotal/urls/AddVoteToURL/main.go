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

func main() {
	// Retrieve API key from environment variable
	apiKey := os.Getenv("VIRUSTOTAL_API_KEY")

	if apiKey == "" {
		log.Fatal("VIRUSTOTAL_API_KEY environment variable must be set")
	}

	// Create logger
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()

	// Create VirusTotal API client
	vtClient, err := virustotal.NewClient(apiKey,
		client.WithLogger(logger),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	urlID := "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20"
	verdict := "harmless" // Can be "harmless" or "malicious"

	result, err := vtClient.URLs.AddVoteToURL(ctx, urlID, verdict)
	if err != nil {
		log.Fatalf("Failed to add vote: %v", err)
	}

	// Print results
	fmt.Printf("\n=== Vote Added to URL ===\n")
	fmt.Printf("Vote ID: %s\n", result.Data.ID)
	fmt.Printf("Type: %s\n", result.Data.Type)
	fmt.Printf("Verdict: %s\n", result.Data.Attributes.Verdict)
	fmt.Printf("Value: %d\n", result.Data.Attributes.Value)
	fmt.Printf("Date: %s\n\n", time.Unix(result.Data.Attributes.Date, 0))

	logger.Info("Vote added successfully",
		zap.String("url_id", urlID),
		zap.String("verdict", verdict))
}
