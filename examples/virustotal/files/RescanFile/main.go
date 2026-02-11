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

	// Request a file rescan by hash (SHA-256, SHA-1, or MD5)
	ctx := context.Background()
	fileID := "44d88612fea8a8f36de82e1278abb02f" // Example MD5 hash (EICAR test file)

	result, err := vtClient.Files.RescanFile(ctx, fileID)
	if err != nil {
		log.Fatalf("Failed to request file rescan: %v", err)
	}

	// Print the rescan request information
	fmt.Printf("\n=== File Rescan Requested ===\n")
	fmt.Printf("Analysis ID: %s\n", result.Data.ID)
	fmt.Printf("Type: %s\n", result.Data.Type)
	fmt.Printf("Analysis URL: %s\n", result.Data.Links.Self)
	fmt.Printf("\nThe file will be reanalyzed with the latest detection signatures\n")
	fmt.Printf("Use the analysis URL to check the status of the scan\n")

	logger.Info("File rescan requested successfully",
		zap.String("file_id", fileID),
		zap.String("analysis_id", result.Data.ID))
}
