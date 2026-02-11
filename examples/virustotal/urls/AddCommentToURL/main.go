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
	commentText := "This URL appears to be safe. #safe #verified"

	result, err := vtClient.URLs.AddCommentToURL(ctx, urlID, commentText)
	if err != nil {
		log.Fatalf("Failed to add comment: %v", err)
	}

	fmt.Printf("\n=== Comment Added ===\n")
	fmt.Printf("Comment ID: %s\n", result.Data.ID)
	fmt.Printf("Type: %s\n", result.Data.Type)
	fmt.Printf("Date: %s\n", time.Unix(result.Data.Attributes.Date, 0))
	fmt.Printf("Text: %s\n", result.Data.Attributes.Text)

	if len(result.Data.Attributes.Tags) > 0 {
		fmt.Printf("Tags: %v\n", result.Data.Attributes.Tags)
	}

	fmt.Printf("\nNote: Words starting with # are automatically converted to tags.\n")

	logger.Info("Comment added successfully",
		zap.String("url_id", urlID),
		zap.String("comment_id", result.Data.ID))
}
