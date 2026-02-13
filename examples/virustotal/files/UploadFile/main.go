package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
	"github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/files"
	"go.uber.org/zap"
)

func main() {

	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		log.Fatal("VT_API_KEY environment variable is required")
	}

	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()

	vtClient, err := virustotal.NewClientFromEnv(
		client.WithLogger(logger),
		client.WithTimeout(300*time.Second), // Longer timeout for file uploads
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Open a file to upload (example: test.txt)
	filePath := "test.txt"
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		log.Fatalf("Failed to get file size info: %v", err)
	}

	ctx := context.Background()

	// Create upload request with progress tracking
	request := &files.UploadFileRequest{
		File:     file,
		Filename: fileInfo.Name(),
		FileSize: fileInfo.Size(),
		// Password: "optional_password", // Optional: for password-protected archives
		ProgressCallback: func(fieldName string, fileName string, bytesWritten int64, totalBytes int64) {
			percentage := float64(bytesWritten) / float64(totalBytes) * 100
			fmt.Printf("\rUploading %s: %.2f%% (%d / %d bytes)", fileName, percentage, bytesWritten, totalBytes)
		},
	}

	fmt.Printf("\n=== Uploading File to VirusTotal ===\n")
	fmt.Printf("File: %s\n", filePath)
	fmt.Printf("Size: %d bytes\n\n", fileInfo.Size())

	result, _, err := vtClient.Files.UploadFile(ctx, request)
	if err != nil {
		log.Fatalf("Failed to upload file: %v", err)
	}

	fmt.Printf("\n\n=== Upload Successful ===\n")
	fmt.Printf("File ID: %s\n", result.Data.ID)
	fmt.Printf("Type: %s\n", result.Data.Type)
	fmt.Printf("Analysis URL: %s\n", result.Data.Links.Self)

	logger.Info("File uploaded successfully",
		zap.String("file", filePath),
		zap.String("file_id", result.Data.ID),
		zap.Int64("size", fileInfo.Size()))
}
