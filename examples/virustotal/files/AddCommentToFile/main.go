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

	// Add a comment to a file
	ctx := context.Background()
	fileID := "44d88612fea8a8f36de82e1278abb02f" // Example MD5 hash (EICAR test file)

	// Comment text with tags (words starting with # become tags)
	commentText := "This is the EICAR test file, used for testing antivirus software #benign #test #eicar"

	result, _, err := vtClient.Files.AddCommentToFile(ctx, fileID, commentText)
	if err != nil {
		log.Fatalf("Failed to add comment to file: %v", err)
	}

	// Print the comment information
	fmt.Printf("\n=== Comment Added Successfully ===\n")
	fmt.Printf("File ID: %s\n", fileID)
	fmt.Printf("Comment ID: %s\n", result.Data.ID)
	fmt.Printf("Comment Type: %s\n", result.Data.Type)
	fmt.Printf("Comment Text: %s\n", result.Data.Attributes.Text)
	fmt.Printf("Date: %s\n", time.Unix(result.Data.Attributes.Date, 0))

	if len(result.Data.Attributes.Tags) > 0 {
		fmt.Printf("\nExtracted Tags:\n")
		for _, tag := range result.Data.Attributes.Tags {
			fmt.Printf("  - %s\n", tag)
		}
	}

	fmt.Printf("\nVotes:\n")
	fmt.Printf("  Harmless: %d\n", result.Data.Attributes.Votes.Harmless)
	fmt.Printf("  Malicious: %d\n", result.Data.Attributes.Votes.Malicious)

	fmt.Printf("\nComment URL: %s\n", result.Data.Links.Self)

	logger.Info("Comment added successfully",
		zap.String("file_id", fileID),
		zap.String("comment_id", result.Data.ID),
		zap.Strings("tags", result.Data.Attributes.Tags))
}
