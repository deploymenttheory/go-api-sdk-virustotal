package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	ipaddresses "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/ip_addresses"
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

	// Get IP address report
	ctx := context.Background()
	ip := "8.8.8.8" // Google DNS

	// Optional: Include relationships
	opts := &ipaddresses.RequestQueryOptions{
		// Relationships: "comments,resolutions",
	}

	report, err := vtClient.IPAddresses.GetIPAddressReport(ctx, ip, opts)
	if err != nil {
		log.Fatalf("Failed to get IP address report: %v", err)
	}

	fmt.Printf("IP Address Report for: %s\n", report.Data.ID)
	fmt.Printf("Type: %s\n\n", report.Data.Type)

	attrs := report.Data.Attributes
	fmt.Printf("Network Information:\n")
	fmt.Printf("  Network: %s\n", attrs.Network)
	fmt.Printf("  ASN: %d\n", attrs.ASN)
	fmt.Printf("  AS Owner: %s\n", attrs.ASOwner)
	fmt.Printf("  Country: %s\n", attrs.Country)
	fmt.Printf("  Continent: %s\n", attrs.Continent)
	fmt.Printf("  RIR: %s\n\n", attrs.RegionalInternetRegistry)

	fmt.Printf("Reputation:\n")
	fmt.Printf("  Reputation Score: %d\n", attrs.Reputation)
	fmt.Printf("  Last Analysis Date: %s\n", time.Unix(attrs.LastAnalysisDate, 0))
	fmt.Printf("  Detection Stats:\n")
	fmt.Printf("    Harmless: %d\n", attrs.LastAnalysisStats.Harmless)
	fmt.Printf("    Malicious: %d\n", attrs.LastAnalysisStats.Malicious)
	fmt.Printf("    Suspicious: %d\n", attrs.LastAnalysisStats.Suspicious)
	fmt.Printf("    Undetected: %d\n", attrs.LastAnalysisStats.Undetected)
	fmt.Printf("    Timeout: %d\n\n", attrs.LastAnalysisStats.Timeout)

	fmt.Printf("Community Votes:\n")
	fmt.Printf("  Harmless: %d\n", attrs.TotalVotes.Harmless)
	fmt.Printf("  Malicious: %d\n\n", attrs.TotalVotes.Malicious)

	if len(attrs.Tags) > 0 {
		fmt.Printf("Tags: %v\n", attrs.Tags)
	}
}
