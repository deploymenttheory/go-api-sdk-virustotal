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

	ctx := context.Background()
	// URL ID can be SHA-256 hash or base64-encoded URL without padding
	urlID := "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20" // Base64 of https://www.example.com

	report, err := vtClient.URLs.GetURLReport(ctx, urlID)
	if err != nil {
		log.Fatalf("Failed to get URL report: %v", err)
	}

	// Print results
	fmt.Printf("\n=== URL Report ===\n")
	fmt.Printf("URL ID: %s\n", report.Data.ID)
	fmt.Printf("Type: %s\n\n", report.Data.Type)

	attrs := report.Data.Attributes
	fmt.Printf("URL Information:\n")
	fmt.Printf("  URL: %s\n", attrs.URL)

	if attrs.Title != "" {
		fmt.Printf("  Title: %s\n", attrs.Title)
	}
	if attrs.LastFinalURL != "" {
		fmt.Printf("  Final URL: %s\n", attrs.LastFinalURL)
	}
	if attrs.LastHTTPResponseCode > 0 {
		fmt.Printf("  HTTP Response Code: %d\n", attrs.LastHTTPResponseCode)
	}

	if attrs.FirstSubmissionDate > 0 {
		fmt.Printf("  First Submission: %s\n", time.Unix(attrs.FirstSubmissionDate, 0))
	}
	if attrs.LastSubmissionDate > 0 {
		fmt.Printf("  Last Submission: %s\n", time.Unix(attrs.LastSubmissionDate, 0))
	}
	fmt.Printf("  Times Submitted: %d\n", attrs.TimesSubmitted)

	if attrs.LastAnalysisDate > 0 {
		fmt.Printf("\nAnalysis:\n")
		fmt.Printf("  Last Analysis: %s\n\n", time.Unix(attrs.LastAnalysisDate, 0))

		fmt.Printf("Detection Statistics:\n")
		fmt.Printf("  Malicious: %d\n", attrs.LastAnalysisStats.Malicious)
		fmt.Printf("  Suspicious: %d\n", attrs.LastAnalysisStats.Suspicious)
		fmt.Printf("  Undetected: %d\n", attrs.LastAnalysisStats.Undetected)
		fmt.Printf("  Harmless: %d\n", attrs.LastAnalysisStats.Harmless)
		fmt.Printf("  Timeout: %d\n\n", attrs.LastAnalysisStats.Timeout)
	}

	fmt.Printf("Community:\n")
	fmt.Printf("  Reputation: %d\n", attrs.Reputation)
	fmt.Printf("  Votes - Harmless: %d\n", attrs.TotalVotes.Harmless)
	fmt.Printf("  Votes - Malicious: %d\n\n", attrs.TotalVotes.Malicious)

	if len(attrs.Categories) > 0 {
		fmt.Printf("Categories:\n")
		count := 0
		for vendor, category := range attrs.Categories {
			if count < 5 {
				fmt.Printf("  %s: %s\n", vendor, category)
				count++
			}
		}
		if len(attrs.Categories) > 5 {
			fmt.Printf("  ... and %d more categories\n", len(attrs.Categories)-5)
		}
	}

	if len(attrs.Tags) > 0 {
		fmt.Printf("\nTags: %v\n", attrs.Tags)
	}

	logger.Info("URL report retrieved successfully",
		zap.String("url_id", urlID),
		zap.Int("malicious_detections", attrs.LastAnalysisStats.Malicious))
}
