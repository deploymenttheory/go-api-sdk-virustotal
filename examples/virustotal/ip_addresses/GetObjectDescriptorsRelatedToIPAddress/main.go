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
	ip := "8.8.8.8"
	relationship := "comments" // Can be: comments, resolutions, communicating_files, referrer_files, etc.

	// Default behavior: Pass nil to automatically fetch all pages
	fmt.Println("=== Get All Object Descriptors (Automatic Pagination) ===")
	fmt.Printf("Fetching object descriptors for %s related to IP: %s\n\n", relationship, ip)

	response, err := vtClient.IPAddresses.GetObjectDescriptorsRelatedToIPAddress(ctx, ip, relationship, nil)
	if err != nil {
		log.Fatalf("Failed to get object descriptors: %v", err)
	}

	fmt.Printf("Total object descriptors retrieved: %d\n\n", len(response.Data))

	// Display first 10 object descriptors
	displayCount := 10
	if len(response.Data) < displayCount {
		displayCount = len(response.Data)
	}

	for i := 0; i < displayCount; i++ {
		descriptor := response.Data[i]
		fmt.Printf("%d. Type: %s\n", i+1, descriptor.Type)
		fmt.Printf("   ID: %s\n", descriptor.ID)
		if len(descriptor.ContextAttributes) > 0 {
			fmt.Printf("   Context Attributes: %v\n", descriptor.ContextAttributes)
		}
		fmt.Println()
	}

	if len(response.Data) > displayCount {
		fmt.Printf("... and %d more descriptors\n", len(response.Data)-displayCount)
	}

	// Compare with full objects endpoint
	fmt.Println("\n=== Efficiency Comparison ===")
	fmt.Println("Object descriptors endpoint returns:")
	fmt.Println("  - Object type and ID only")
	fmt.Println("  - Context attributes (if any)")
	fmt.Println("  - Much smaller response size")
	fmt.Println("\nUse this when you only need to know which objects exist,")
	fmt.Println("not their full details.")
}
