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

	// Resolution ID format: "ip_address-domain"
	// Example: "93.184.216.34-example.com"
	resolutionID := "93.184.216.34-example.com"

	result, err := vtClient.Domains.GetDNSResolutionObject(ctx, resolutionID)
	if err != nil {
		log.Fatalf("Failed to get DNS resolution: %v", err)
	}

	// Print DNS resolution information
	fmt.Printf("\n=== DNS Resolution Object ===\n")
	fmt.Printf("Resolution ID: %s\n", result.Data.ID)
	fmt.Printf("Type: %s\n\n", result.Data.Type)

	attrs := result.Data.Attributes
	fmt.Printf("Resolution Details:\n")
	fmt.Printf("  IP Address: %s\n", attrs.IPAddress)
	fmt.Printf("  Host Name: %s\n", attrs.HostName)

	if attrs.Date > 0 {
		fmt.Printf("  Date: %s\n", time.Unix(attrs.Date, 0).Format("2006-01-02 15:04:05"))
	}

	if attrs.Resolver != "" {
		fmt.Printf("  Resolver: %s\n", attrs.Resolver)
	}

	fmt.Printf("\nThis object represents the relationship between a domain and IP address,")
	fmt.Printf("\nshowing when the domain resolved to the specific IP.\n")

	logger.Info("DNS resolution retrieved successfully",
		zap.String("resolution_id", resolutionID),
		zap.String("ip_address", attrs.IPAddress),
		zap.String("host_name", attrs.HostName))
}
