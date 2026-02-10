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

	result, err := vtClient.URLs.GetVotesOnURL(ctx, urlID, nil)
	if err != nil {
		log.Fatalf("Failed to get votes: %v", err)
	}

	// Print results
	fmt.Printf("\n=== Votes on URL ===\n")
	fmt.Printf("Total Votes: %d\n\n", len(result.Data))

	harmlessCount := 0
	maliciousCount := 0

	for i, vote := range result.Data {
		fmt.Printf("Vote %d:\n", i+1)
		fmt.Printf("  ID: %s\n", vote.ID)
		fmt.Printf("  Date: %s\n", time.Unix(vote.Attributes.Date, 0))
		fmt.Printf("  Verdict: %s\n", vote.Attributes.Verdict)
		fmt.Printf("  Value: %d\n\n", vote.Attributes.Value)

		if vote.Attributes.Verdict == "harmless" {
			harmlessCount++
		} else if vote.Attributes.Verdict == "malicious" {
			maliciousCount++
		}
	}

	fmt.Printf("Summary:\n")
	fmt.Printf("  Harmless votes: %d\n", harmlessCount)
	fmt.Printf("  Malicious votes: %d\n", maliciousCount)

	logger.Info("Votes retrieved successfully",
		zap.String("url_id", urlID),
		zap.Int("vote_count", len(result.Data)))
}
