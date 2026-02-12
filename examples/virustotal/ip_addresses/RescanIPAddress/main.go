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
		client.WithTimeout(30*time.Second),
		client.WithRetryCount(3),
		client.WithDebug(),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Request a rescan of an IP address
	ctx := context.Background()
	ip := "8.8.8.8" // Google DNS

	result, _, err := vtClient.IPAddresses.RescanIPAddress(ctx, ip)
	if err != nil {
		log.Fatalf("Failed to request IP address rescan: %v", err)
	}

	fmt.Printf("IP Address Rescan Initiated: %s\n", ip)
	fmt.Printf("Analysis Type: %s\n", result.Data.Type)
	fmt.Printf("Analysis ID: %s\n\n", result.Data.ID)
	fmt.Printf("Analysis URL:\n  %s\n\n", result.Data.Links.Self)
	fmt.Println("Note: The analysis may take a few moments to complete.")
	fmt.Println("Use the analysis ID above to retrieve the updated results.")

	logger.Info("IP address rescan requested successfully",
		zap.String("ip", ip),
		zap.String("analysis_id", result.Data.ID))
}
