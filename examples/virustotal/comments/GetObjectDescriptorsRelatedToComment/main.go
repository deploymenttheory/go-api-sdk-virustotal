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
	commentID := "u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345"
	relationship := "author"

	result, err := vtClient.Comments.GetObjectDescriptorsRelatedToComment(ctx, commentID, relationship, nil)
	if err != nil {
		log.Fatalf("Failed to get object descriptors: %v", err)
	}

	// Print results
	fmt.Printf("\n=== Object Descriptors Related to Comment ===\n")
	fmt.Printf("Comment ID: %s\n", commentID)
	fmt.Printf("Relationship: %s\n", relationship)
	fmt.Printf("Total Descriptors: %d\n\n", len(result.Data))

	fmt.Printf("Object IDs:\n")
	for i, descriptor := range result.Data {
		fmt.Printf("  %d. Type: %s, ID: %s\n", i+1, descriptor.Type, descriptor.ID)
	}

	fmt.Printf("\nNote: This endpoint returns only IDs, not full objects.\n")
	fmt.Printf("Use GetObjectsRelatedToComment for full object details.\n")

	logger.Info("Object descriptors retrieved successfully",
		zap.String("comment_id", commentID),
		zap.String("relationship", relationship),
		zap.Int("descriptor_count", len(result.Data)))
}
