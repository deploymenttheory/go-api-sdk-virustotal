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

	// Get download URL for a file by hash (SHA-256, SHA-1, or MD5)
	// Note: This requires a premium API key
	ctx := context.Background()
	fileID := "44d88612fea8a8f36de82e1278abb02f" // Example MD5 hash (EICAR test file)

	downloadURL, err := vtClient.Files.GetFileDownloadURL(ctx, fileID)
	if err != nil {
		log.Fatalf("Failed to get file download URL: %v", err)
	}

	// Print the download URL
	fmt.Printf("\n=== File Download URL ===\n")
	fmt.Printf("File ID: %s\n", fileID)
	fmt.Printf("Download URL: %s\n", downloadURL.Data)
	fmt.Printf("\nNote: This feature requires a premium API key\n")
	fmt.Printf("The URL is valid for a limited time\n")

	logger.Info("File download URL retrieved successfully",
		zap.String("file_id", fileID),
		zap.String("download_url", downloadURL.Data))
}
