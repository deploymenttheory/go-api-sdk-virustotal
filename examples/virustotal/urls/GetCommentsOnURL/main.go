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

	result, err := vtClient.URLs.GetCommentsOnURL(ctx, urlID, nil)
	if err != nil {
		log.Fatalf("Failed to get comments: %v", err)
	}

	// Print results
	fmt.Printf("\n=== Comments on URL ===\n")
	fmt.Printf("Total Comments: %d\n\n", len(result.Data))

	for i, comment := range result.Data {
		fmt.Printf("Comment %d:\n", i+1)
		fmt.Printf("  ID: %s\n", comment.ID)
		fmt.Printf("  Type: %s\n", comment.Type)

		// Extract attributes from map
		if date, ok := comment.Attributes["date"].(float64); ok {
			fmt.Printf("  Date: %s\n", time.Unix(int64(date), 0))
		}
		if text, ok := comment.Attributes["text"].(string); ok {
			fmt.Printf("  Text: %s\n", text)
		}
		if tags, ok := comment.Attributes["tags"].([]interface{}); ok && len(tags) > 0 {
			fmt.Printf("  Tags: %v\n", tags)
		}
		if votes, ok := comment.Attributes["votes"].(map[string]interface{}); ok {
			fmt.Printf("  Votes - Harmless: %.0f, Malicious: %.0f\n",
				votes["harmless"],
				votes["malicious"])
		}

		fmt.Println()
	}

	logger.Info("Comments retrieved successfully",
		zap.String("url_id", urlID),
		zap.Int("comment_count", len(result.Data)))
}
