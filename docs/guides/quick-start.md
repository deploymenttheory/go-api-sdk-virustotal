# Quick Start Guide

Get up and running with the VirusTotal Go SDK in minutes.

## Prerequisites

- Go 1.25 or higher
- A VirusTotal API key ([Get one here](https://www.virustotal.com/gui/join-us))

## Installation

```bash
go get github.com/deploymenttheory/go-api-sdk-virustotal
```

## Your First API Call

Here's a complete example that checks a file hash:

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"

    "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
    "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/files"
)

func main() {
    // Step 1: Create the client with your API key
    apiClient, err := client.NewClient(os.Getenv("VT_API_KEY"))
    if err != nil {
        log.Fatal(err)
    }

    // Step 2: Create a service (files, URLs, domains, etc.)
    filesService := files.NewService(apiClient)

    // Step 3: Make an API call
    result, resp, err := filesService.GetFileReport(
        context.Background(),
        "44d88612fea8a8f36de82e1278abb02f", // EICAR test file hash
    )
    if err != nil {
        log.Fatal(err)
    }

    // Step 4: Use the results
    fmt.Printf("File: %s\n", result.Data.Attributes.MeaningfulName)
    fmt.Printf("Status Code: %d\n", resp.StatusCode)
    fmt.Printf("Malicious: %d\n", result.Data.Attributes.LastAnalysisStats.Malicious)
    fmt.Printf("Suspicious: %d\n", result.Data.Attributes.LastAnalysisStats.Suspicious)
    fmt.Printf("Harmless: %d\n", result.Data.Attributes.LastAnalysisStats.Harmless)
}
```

**Run it:**

```bash
export VT_API_KEY="your-api-key-here"
go run main.go
```

**Output:**

```text
File: eicar.com
Status Code: 200
Malicious: 63
Suspicious: 0
Harmless: 0
```

## Common Operations

### Check a URL

```go
import "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/urls"

urlsService := urls.NewService(apiClient)

result, _, err := urlsService.GetURLReport(
    context.Background(),
    "https://www.example.com",
)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("URL: %s\n", result.Data.Attributes.URL)
fmt.Printf("Malicious: %d\n", result.Data.Attributes.LastAnalysisStats.Malicious)
```

### Check a Domain

```go
import "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/domains"

domainsService := domains.NewService(apiClient)

result, _, err := domainsService.GetDomainReport(
    context.Background(),
    "example.com",
)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Domain: %s\n", result.Data.ID)
fmt.Printf("Categories: %v\n", result.Data.Attributes.Categories)
```

### Check an IP Address

```go
import "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/ip_addresses"

ipService := ip_addresses.NewService(apiClient)

result, _, err := ipService.GetIPAddressReport(
    context.Background(),
    "8.8.8.8",
)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("IP: %s\n", result.Data.ID)
fmt.Printf("Country: %s\n", result.Data.Attributes.Country)
fmt.Printf("ASN: %d\n", result.Data.Attributes.ASN)
```

### Upload and Scan a File

```go
import (
    "os"
    "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/files"
)

filesService := files.NewService(apiClient)

// Open the file
file, err := os.Open("/path/to/file.exe")
if err != nil {
    log.Fatal(err)
}
defer file.Close()

// Get file info
fileInfo, _ := file.Stat()

// Create upload request
uploadReq := &files.UploadFileRequest{
    File:     file,
    Filename: fileInfo.Name(),
    FileSize: fileInfo.Size(),
}

// Upload and scan
result, _, err := filesService.UploadFile(context.Background(), uploadReq)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Analysis ID: %s\n", result.Data.ID)
fmt.Printf("Check status at: %s\n", result.Data.Links.Self)
```

## Error Handling

Always check for errors and handle common cases:

```go
result, resp, err := filesService.GetFileReport(ctx, hash)

if err != nil {
    // Check for specific error types
    if client.IsNotFound(err) {
        fmt.Println("File not found - it may not have been scanned yet")
        return
    }

    if client.IsUnauthorized(err) {
        fmt.Println("Invalid API key")
        return
    }

    if client.IsQuotaExceeded(err) {
        fmt.Println("API quota exceeded - wait before retrying")
        return
    }

    // Other errors
    log.Fatal(err)
}

// Success - use the result
fmt.Printf("File: %s\n", result.Data.Attributes.MeaningfulName)
```

## Response Metadata

Every API call returns response metadata:

```go
result, resp, err := filesService.GetFileReport(ctx, hash)

// Access response metadata
fmt.Printf("Status Code: %d\n", resp.StatusCode)
fmt.Printf("Request Duration: %v\n", resp.Duration)
fmt.Printf("Response Size: %d bytes\n", resp.Size)
fmt.Printf("Received At: %v\n", resp.ReceivedAt)

// Check rate limits
rateLimits := client.GetRateLimitHeaders(resp)
fmt.Printf("Daily Remaining: %d/%d\n",
    rateLimits.DailyRemaining,
    rateLimits.DailyLimit)
```

## Next Steps

### Production Configuration

For production use, configure the client with appropriate settings:

```go
import (
    "time"
    "go.uber.org/zap"
)

logger, _ := zap.NewProduction()

apiClient, err := client.NewClient(
    os.Getenv("VT_API_KEY"),
    client.WithTimeout(30*time.Second),
    client.WithRetryCount(3),
    client.WithLogger(logger),
)
```

**Learn more:**

- **[Authentication](authentication.md)** - Secure API key management
- **[Timeouts & Retries](timeouts-retries.md)** - Configure resilience
- **[Structured Logging](logging.md)** - Production logging with zap

### Advanced Features

Enhance your integration with advanced client features:

**Observability:**

- **[OpenTelemetry Tracing](opentelemetry.md)** - Distributed tracing for monitoring
- **[Debug Mode](debugging.md)** - Detailed request/response inspection

**Network Configuration:**

- **[TLS/SSL Configuration](tls-configuration.md)** - Custom certificates and mutual TLS
- **[Proxy Support](proxy.md)** - Route traffic through proxies
- **[Custom Headers](custom-headers.md)** - Add tracking or metadata headers

### API Coverage

Explore all available services:

**IOC Reputation & Enrichment:**
- Files - Upload, scan, download, and retrieve file reports
- URLs - Scan URLs and retrieve analysis results
- Domains - Domain reputation and DNS information
- IP Addresses - IP address reputation and WHOIS data
- Analyses - Retrieve analysis results and submissions
- Comments - Manage comments on IOCs
- Code Insights - Analyze code snippets
- File Behaviours - Retrieve file behavior reports
- Attack Techniques/Tactics - MITRE ATT&CK framework integration
- Saved Searches - Manage saved VirusTotal searches

**VT Enterprise:**
- Collections - Manage collections of IOCs
- Search and Metadata - Search for IOCs and retrieve metadata

### Examples

Check out the [examples directory](../../examples/virustotal/) for complete working examples:

- File operations (upload, scan, download)
- URL scanning
- Domain and IP lookups
- Analysis retrieval
- Comment management
- Relationship queries

## Troubleshooting

### "Invalid API Key" Error

```go
// Verify your API key is set correctly
apiKey := os.Getenv("VT_API_KEY")
if apiKey == "" {
    log.Fatal("VT_API_KEY environment variable not set")
}

// Check for authentication errors
if err != nil && client.IsUnauthorized(err) {
    log.Fatal("Invalid API key - check your credentials")
}
```

### "Rate Limit Exceeded" Error

```go
// Check rate limit headers
rateLimits := client.GetRateLimitHeaders(resp)
fmt.Printf("Remaining: %d/%d\n",
    rateLimits.DailyRemaining,
    rateLimits.DailyLimit)

// Handle rate limit errors
if client.IsQuotaExceeded(err) {
    log.Println("Rate limit exceeded - waiting 60 seconds")
    time.Sleep(60 * time.Second)
    // Retry request
}
```

### "File Not Found" Error

```go
// Handle not found errors
if client.IsNotFound(err) {
    log.Println("File not in VirusTotal database")
    log.Println("Upload the file to scan it")

    // Upload file...
}
```

## Getting Help

- **[Full Documentation](../../README.md)** - Complete SDK documentation
- **[API Reference](https://docs.virustotal.com/reference/overview)** - VirusTotal API documentation
- **[GitHub Issues](https://github.com/deploymenttheory/go-api-sdk-virustotal/issues)** - Report bugs or request features
- **[GoDoc](https://pkg.go.dev/github.com/deploymenttheory/go-api-sdk-virustotal)** - Package documentation

## Complete Example

Here's a complete example with error handling, logging, and rate limit checking:

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "time"

    "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
    "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/files"
    "go.uber.org/zap"
)

func main() {
    // Initialize logger
    logger, _ := zap.NewProduction()
    defer logger.Sync()

    // Create client with production settings
    apiClient, err := client.NewClient(
        os.Getenv("VT_API_KEY"),
        client.WithTimeout(30*time.Second),
        client.WithRetryCount(3),
        client.WithLogger(logger),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Create service
    filesService := files.NewService(apiClient)

    // Make API call with context
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    result, resp, err := filesService.GetFileReport(ctx, "44d88612fea8a8f36de82e1278abb02f")

    // Handle errors
    if err != nil {
        switch {
        case client.IsNotFound(err):
            log.Println("File not found in VirusTotal database")
            return
        case client.IsQuotaExceeded(err):
            log.Println("Rate limit exceeded")
            return
        case client.IsUnauthorized(err):
            log.Fatal("Invalid API key")
        default:
            log.Fatal(err)
        }
    }

    // Log response metadata
    logger.Info("API call successful",
        zap.Int("status_code", resp.StatusCode),
        zap.Duration("duration", resp.Duration),
        zap.Int64("size", resp.Size),
    )

    // Check rate limits
    rateLimits := client.GetRateLimitHeaders(resp)
    logger.Info("Rate limit status",
        zap.Int("daily_remaining", rateLimits.DailyRemaining),
        zap.Int("daily_limit", rateLimits.DailyLimit),
    )

    // Use results
    fmt.Printf("File: %s\n", result.Data.Attributes.MeaningfulName)
    fmt.Printf("SHA256: %s\n", result.Data.Attributes.SHA256)
    fmt.Printf("Malicious: %d\n", result.Data.Attributes.LastAnalysisStats.Malicious)
    fmt.Printf("Harmless: %d\n", result.Data.Attributes.LastAnalysisStats.Harmless)
}
```

---

**Ready to build?** Start with this quick start and explore the [configuration guides](../guides/) to customize the SDK for your needs!
