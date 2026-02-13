# Go SDK for VirusTotal API v3

[![Go Report Card](https://goreportcard.com/badge/github.com/deploymenttheory/go-api-sdk-virustotal)](https://goreportcard.com/report/github.com/deploymenttheory/go-api-sdk-virustotal)
[![GoDoc](https://pkg.go.dev/badge/github.com/deploymenttheory/go-api-sdk-virustotal)](https://pkg.go.dev/github.com/deploymenttheory/go-api-sdk-virustotal)
[![License](https://img.shields.io/github/license/deploymenttheory/go-api-sdk-virustotal)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/deploymenttheory/go-api-sdk-virustotal)](https://go.dev/)
[![Release](https://img.shields.io/github/v/release/deploymenttheory/go-api-sdk-virustotal)](https://github.com/deploymenttheory/go-api-sdk-virustotal/releases)
[![codecov](https://codecov.io/gh/deploymenttheory/go-api-sdk-virustotal/graph/badge.svg)](https://codecov.io/gh/deploymenttheory/go-api-sdk-virustotal)
[![Tests](https://github.com/deploymenttheory/go-api-sdk-virustotal/workflows/Tests/badge.svg)](https://github.com/deploymenttheory/go-api-sdk-virustotal/actions)
![Status: Alpha](https://img.shields.io/badge/status-alpha-orange)

A comprehensive Go client library for the [VirusTotal API v3](https://docs.virustotal.com/reference/overview).

## Features

- **Complete API Coverage**: Support for Files, URLs, Domains, IP Addresses, Analyses, and more
- **Type-Safe**: Strongly typed request/response models
- **Pagination Support**: Automatic and manual pagination for list endpoints
- **Error Handling**: Comprehensive error types with detailed API error information
- **Response Metadata**: Access to HTTP status codes, headers, response timing, and body size
- **File Upload**: Support for multipart file uploads with progress callbacks
- **Context Support**: Context-aware operations for timeouts and cancellation
- **Rate Limiting**: Built-in respect for API rate limits
- **Structured Logging**: Integration with zap for structured logging
- **Testing**: Comprehensive unit tests with httpmock and acceptance tests

## Installation

```bash
go get github.com/deploymenttheory/go-api-sdk-virustotal
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
    "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/files"
)

func main() {
    // Create client
    apiClient, err := client.NewClient("your-api-key")
    if err != nil {
        log.Fatal(err)
    }

    // Create files service
    filesService := files.NewService(apiClient)

    // Get file report
    result, resp, err := filesService.GetFileReport(context.Background(), "44d88612fea8a8f36de82e1278abb02f")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("File: %s\n", result.Data.Attributes.MeaningfulName)
    fmt.Printf("Status Code: %d\n", resp.StatusCode)
    fmt.Printf("Malicious: %d\n", result.Data.Attributes.LastAnalysisStats.Malicious)
}
```

## Services

### IOC Reputation and Enrichment
- **Files**: Upload, scan, download, and retrieve file reports
- **URLs**: Scan URLs and retrieve analysis results
- **Domains**: Domain reputation and DNS information
- **IP Addresses**: IP address reputation and WHOIS data
- **Analyses**: Retrieve analysis results and submissions
- **Comments**: Manage comments on IOCs
- **Code Insights**: Analyze code snippets
- **File Behaviours**: Retrieve file behavior reports
- **Attack Techniques/Tactics**: MITRE ATT&CK framework integration
- **Saved Searches**: Manage saved VirusTotal searches

## Response Metadata

All SDK functions return `*interfaces.Response` containing:

```go
type Response struct {
    StatusCode int           // HTTP status code
    Status     string        // HTTP status text
    Headers    http.Header   // Response headers
    Body       []byte        // Raw response body
    Duration   time.Duration // Request duration
    ReceivedAt time.Time     // Response timestamp
    Size       int64         // Response body size
}
```

Helper functions in `client` package:

```go
// Check response status
if client.IsResponseSuccess(resp) {
    // Handle 2xx response
}

// Get rate limit headers
rateLimitHeaders := client.GetRateLimitHeaders(resp)
```

## Configuration Options

```go
apiClient, err := client.NewClient("your-api-key",
    client.WithBaseURL("https://www.virustotal.com/api/v3"),
    client.WithTimeout(30*time.Second),
    client.WithLogger(zapLogger),
    client.WithRetryCount(3),
    client.WithRetryWaitTime(5*time.Second),
)
```

## Documentation

- [VirusTotal API v3 Documentation](https://docs.virustotal.com/reference/overview)
- [GoDoc](https://pkg.go.dev/github.com/deploymenttheory/go-api-sdk-virustotal)

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/deploymenttheory/go-api-sdk-virustotal/issues)
- **Documentation**: [API Docs](https://docs.virustotal.com/reference/overview)

## Disclaimer

This is an unofficial SDK and is not affiliated with or endorsed by VirusTotal or Chronicle LLC.
