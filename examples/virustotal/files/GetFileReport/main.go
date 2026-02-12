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

	// Get file report by hash (SHA-256, SHA-1, or MD5)
	ctx := context.Background()
	fileID := "44d88612fea8a8f36de82e1278abb02f" // Example MD5 hash (EICAR test file)

	report, _, err := vtClient.Files.GetFileReport(ctx, fileID)
	if err != nil {
		log.Fatalf("Failed to get file report: %v", err)
	}

	fmt.Printf("\n=== File Report ===\n")
	fmt.Printf("File ID: %s\n", report.Data.ID)
	fmt.Printf("Type: %s\n\n", report.Data.Type)

	attrs := report.Data.Attributes
	fmt.Printf("File Information:\n")
	fmt.Printf("  Size: %d bytes\n", attrs.Size)
	fmt.Printf("  Type: %s\n", attrs.Type)
	fmt.Printf("  SHA-256: %s\n", attrs.SHA256)
	fmt.Printf("  SHA-1: %s\n", attrs.SHA1)
	fmt.Printf("  MD5: %s\n\n", attrs.MD5)

	fmt.Printf("Analysis:\n")
	fmt.Printf("  First Submission: %s\n", time.Unix(attrs.FirstSubmissionDate, 0))
	fmt.Printf("  Last Analysis: %s\n", time.Unix(attrs.LastAnalysisDate, 0))
	fmt.Printf("  Times Submitted: %d\n\n", attrs.TimesSubmitted)

	fmt.Printf("Detection Statistics:\n")
	fmt.Printf("  Malicious: %d\n", attrs.LastAnalysisStats.Malicious)
	fmt.Printf("  Suspicious: %d\n", attrs.LastAnalysisStats.Suspicious)
	fmt.Printf("  Undetected: %d\n", attrs.LastAnalysisStats.Undetected)
	fmt.Printf("  Harmless: %d\n", attrs.LastAnalysisStats.Harmless)
	fmt.Printf("  Failure: %d\n", attrs.LastAnalysisStats.Failure)
	fmt.Printf("  Timeout: %d\n", attrs.LastAnalysisStats.Timeout)
	fmt.Printf("  Confirmed-Timeout: %d\n", attrs.LastAnalysisStats.ConfirmedTimeout)
	fmt.Printf("  Type-Unsupported: %d\n\n", attrs.LastAnalysisStats.TypeUnsupported)

	fmt.Printf("Community:\n")
	fmt.Printf("  Reputation: %d\n", attrs.Reputation)
	fmt.Printf("  Votes - Harmless: %d\n", attrs.TotalVotes.Harmless)
	fmt.Printf("  Votes - Malicious: %d\n\n", attrs.TotalVotes.Malicious)

	if len(attrs.Tags) > 0 {
		fmt.Printf("Tags: %v\n", attrs.Tags)
	}

	logger.Info("File report retrieved successfully",
		zap.String("file_id", fileID),
		zap.Int("malicious_detections", attrs.LastAnalysisStats.Malicious))
}
