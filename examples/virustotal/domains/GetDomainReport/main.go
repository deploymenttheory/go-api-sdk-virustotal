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
	domain := "example.com" // Example domain

	report, err := vtClient.Domains.GetDomainReport(ctx, domain)
	if err != nil {
		log.Fatalf("Failed to get domain report: %v", err)
	}

	fmt.Printf("\n=== Domain Report ===\n")
	fmt.Printf("Domain: %s\n", report.Data.ID)
	fmt.Printf("Type: %s\n\n", report.Data.Type)

	attrs := report.Data.Attributes
	fmt.Printf("Domain Information:\n")

	if attrs.Registrar != "" {
		fmt.Printf("  Registrar: %s\n", attrs.Registrar)
	}
	if attrs.CreationDate > 0 {
		fmt.Printf("  Creation Date: %s\n", time.Unix(attrs.CreationDate, 0))
	}
	if attrs.ExpirationDate > 0 {
		fmt.Printf("  Expiration Date: %s\n", time.Unix(attrs.ExpirationDate, 0))
	}
	if len(attrs.Nameservers) > 0 {
		fmt.Printf("  Name Servers: %v\n", attrs.Nameservers)
	}

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
			if count < 5 { // Show first 5
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

	logger.Info("Domain report retrieved successfully",
		zap.String("domain", domain),
		zap.Int("malicious_detections", attrs.LastAnalysisStats.Malicious))
}
