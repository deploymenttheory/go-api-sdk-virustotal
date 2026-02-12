package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal"
)

func main() {
	// Initialize the VirusTotal client
	client, err := virustotal.NewClientFromEnv()
	if err != nil {
		log.Fatalf("Failed to create VirusTotal client: %v", err)
	}

	// Operation ID (obtained from asynchronous operations)
	operationID := os.Getenv("OPERATION_ID")
	if operationID == "" {
		log.Fatal("OPERATION_ID environment variable is required")
	}

	// Get the operation status
	ctx := context.Background()
	operation, _, err := client.Analyses.GetOperation(ctx, operationID)
	if err != nil {
		log.Fatalf("Failed to get operation: %v", err)
	}

	// Pretty print the result
	jsonData, err := json.MarshalIndent(operation, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}

	fmt.Println("Operation Details:")
	fmt.Println(string(jsonData))

	// Print summary
	fmt.Printf("\nOperation Summary:\n")
	fmt.Printf("  ID: %s\n", operation.Data.ID)
	fmt.Printf("  Status: %s\n", operation.Data.Attributes.Status)

	// Poll until operation is complete (example)
	if operation.Data.Attributes.Status == "running" {
		fmt.Println("\nOperation is still running. Polling for completion...")

		maxAttempts := 10
		pollInterval := 5 * time.Second

		for attempt := 1; attempt <= maxAttempts; attempt++ {
			fmt.Printf("  Attempt %d/%d...\n", attempt, maxAttempts)
			time.Sleep(pollInterval)

			operation, _, err = client.Analyses.GetOperation(ctx, operationID)
			if err != nil {
				log.Fatalf("Failed to poll operation: %v", err)
			}

			if operation.Data.Attributes.Status == "finished" {
				fmt.Println("  Operation completed successfully!")
				break
			} else if operation.Data.Attributes.Status == "aborted" {
				fmt.Println("  Operation was aborted!")
				break
			}
		}

		if operation.Data.Attributes.Status == "running" {
			fmt.Printf("  Operation still running after %d attempts.\n", maxAttempts)
		}
	} else {
		fmt.Printf("\nOperation status: %s\n", operation.Data.Attributes.Status)
	}
}
