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
	// Comment ID format: {prefix}-{item_id}-{random}
	// Prefixes: d=domain, f=file, g=graph, i=IP, u=URL
	commentID := "u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345"

	result, err := vtClient.Comments.GetComment(ctx, commentID)
	if err != nil {
		log.Fatalf("Failed to get comment: %v", err)
	}

	// Print results
	fmt.Printf("\n=== Comment Details ===\n")
	fmt.Printf("Comment ID: %s\n", result.Data.ID)
	fmt.Printf("Type: %s\n", result.Data.Type)
	fmt.Printf("Date: %s\n\n", time.Unix(result.Data.Attributes.Date, 0))

	fmt.Printf("Content:\n")
	fmt.Printf("  Text: %s\n", result.Data.Attributes.Text)
	fmt.Printf("  HTML: %s\n", result.Data.Attributes.HTML)

	if len(result.Data.Attributes.Tags) > 0 {
		fmt.Printf("  Tags: %v\n", result.Data.Attributes.Tags)
	}

	fmt.Printf("\nVotes:\n")
	fmt.Printf("  Positive: %d\n", result.Data.Attributes.Votes.Positive)
	fmt.Printf("  Negative: %d\n", result.Data.Attributes.Votes.Negative)
	fmt.Printf("  Abuse: %d\n\n", result.Data.Attributes.Votes.Abuse)

	logger.Info("Comment retrieved successfully",
		zap.String("comment_id", commentID))
}
