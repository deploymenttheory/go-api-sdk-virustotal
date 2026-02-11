package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	virustotal "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal"
)

func main() {
	// Initialize the VirusTotal client
	client, err := virustotal.NewClientFromEnv()
	if err != nil {
		log.Fatalf("Failed to create VirusTotal client: %v", err)
	}

	// Submission ID (obtained from file/URL submission)
	submissionID := os.Getenv("SUBMISSION_ID")
	if submissionID == "" {
		log.Fatal("SUBMISSION_ID environment variable is required")
	}

	// Get the submission
	ctx := context.Background()
	submission, err := client.Analyses.GetSubmission(ctx, submissionID)
	if err != nil {
		log.Fatalf("Failed to get submission: %v", err)
	}

	// Pretty print the result
	jsonData, err := json.MarshalIndent(submission, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}

	fmt.Println("Submission Details:")
	fmt.Println(string(jsonData))

	// Print summary
	fmt.Printf("\nSubmission Summary:\n")
	fmt.Printf("  ID: %s\n", submission.Data.ID)
	fmt.Printf("  Date: %s\n", time.Unix(submission.Data.Attributes.Date, 0).Format(time.RFC3339))
	if submission.Data.Attributes.Interface != "" {
		fmt.Printf("  Interface: %s\n", submission.Data.Attributes.Interface)
	}
	if submission.Data.Attributes.Country != "" {
		fmt.Printf("  Country: %s\n", submission.Data.Attributes.Country)
	}
	if submission.Data.Attributes.City != "" {
		fmt.Printf("  City: %s\n", submission.Data.Attributes.City)
	}
	if submission.Data.Attributes.Name != "" {
		fmt.Printf("  Filename: %s\n", submission.Data.Attributes.Name)
	}
	if submission.Data.Attributes.SourceKey != "" {
		fmt.Printf("  Source Key: %s\n", submission.Data.Attributes.SourceKey)
	}
}
