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
	// Comment ID format: {prefix}-{item_id}-{random}
	commentID := "u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345"

	_, err = vtClient.Comments.DeleteComment(ctx, commentID)
	if err != nil {
		log.Fatalf("Failed to delete comment: %v", err)
	}

	fmt.Printf("\n=== Comment Deleted ===\n")
	fmt.Printf("Comment ID: %s\n", commentID)
	fmt.Printf("Status: Successfully deleted\n\n")

	fmt.Printf("Note: Only the comment author or VirusTotal administrators can delete comments.\n")

	logger.Info("Comment deleted successfully",
		zap.String("comment_id", commentID))
}
