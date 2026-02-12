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
	urlID := "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20"
	relationship := "comments" // Can be: comments, analyses, collections, etc.

	result, _, err := vtClient.URLs.GetObjectsRelatedToURL(ctx, urlID, relationship, nil)
	if err != nil {
		log.Fatalf("Failed to get related objects: %v", err)
	}

	fmt.Printf("\n=== Objects Related to URL ===\n")
	fmt.Printf("Relationship: %s\n", relationship)
	fmt.Printf("Total Objects: %d\n\n", len(result.Data))

	for i, obj := range result.Data {
		fmt.Printf("Object %d:\n", i+1)
		fmt.Printf("  ID: %s\n", obj.ID)
		fmt.Printf("  Type: %s\n", obj.Type)

		// Extract attributes from map (structure varies by object type)
		if text, ok := obj.Attributes["text"].(string); ok && text != "" {
			fmt.Printf("  Text: %s\n", text)
		}

		fmt.Println()
	}

	logger.Info("Related objects retrieved successfully",
		zap.String("url_id", urlID),
		zap.String("relationship", relationship),
		zap.Int("object_count", len(result.Data)))
}
