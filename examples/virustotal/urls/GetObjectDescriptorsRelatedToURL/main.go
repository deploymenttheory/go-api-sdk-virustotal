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
	urlID := "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20"
	relationship := "comments"

	result, _, err := vtClient.URLs.GetObjectDescriptorsRelatedToURL(ctx, urlID, relationship, nil)
	if err != nil {
		log.Fatalf("Failed to get object descriptors: %v", err)
	}

	fmt.Printf("\n=== Object Descriptors Related to URL ===\n")
	fmt.Printf("Relationship: %s\n", relationship)
	fmt.Printf("Total Descriptors: %d\n\n", len(result.Data))

	fmt.Printf("Object IDs:\n")
	for i, descriptor := range result.Data {
		fmt.Printf("  %d. Type: %s, ID: %s\n", i+1, descriptor.Type, descriptor.ID)
	}

	fmt.Printf("\nNote: This endpoint returns only IDs, not full objects.\n")
	fmt.Printf("Use GetObjectsRelatedToURL for full object details.\n")

	logger.Info("Object descriptors retrieved successfully",
		zap.String("url_id", urlID),
		zap.String("relationship", relationship),
		zap.Int("descriptor_count", len(result.Data)))
}
