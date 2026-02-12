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
	commentID := "u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345"
	relationship := "author" // Currently only "author" is supported

	result, _, err := vtClient.Comments.GetObjectsRelatedToComment(ctx, commentID, relationship, nil)
	if err != nil {
		log.Fatalf("Failed to get related objects: %v", err)
	}

	fmt.Printf("\n=== Objects Related to Comment ===\n")
	fmt.Printf("Comment ID: %s\n", commentID)
	fmt.Printf("Relationship: %s\n", relationship)
	fmt.Printf("Total Objects: %d\n\n", len(result.Data))

	for i, obj := range result.Data {
		fmt.Printf("Object %d:\n", i+1)
		fmt.Printf("  ID: %s\n", obj.ID)
		fmt.Printf("  Type: %s\n", obj.Type)

		if obj.Attributes.Text != "" {
			fmt.Printf("  Text: %s\n", obj.Attributes.Text)
		}

		fmt.Println()
	}

	logger.Info("Related objects retrieved successfully",
		zap.String("comment_id", commentID),
		zap.String("relationship", relationship),
		zap.Int("object_count", len(result.Data)))
}
