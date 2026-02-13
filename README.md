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

### HTTP Client Configuration

The SDK includes a powerful HTTP client with production-ready configuration options:

- **[Authentication](docs/guides/authentication.md)** - Secure API key management
- **[Timeouts & Retries](docs/guides/timeouts-retries.md)** - Configurable timeouts and automatic retry logic
- **[TLS/SSL Configuration](docs/guides/tls-configuration.md)** - Custom certificates, mutual TLS, and security settings
- **[Proxy Support](docs/guides/proxy.md)** - HTTP/HTTPS/SOCKS5 proxy configuration
- **[Custom Headers](docs/guides/custom-headers.md)** - Global and per-request header management
- **[Structured Logging](docs/guides/logging.md)** - Integration with zap for production logging
- **[OpenTelemetry Tracing](docs/guides/opentelemetry.md)** - Distributed tracing and observability
- **[Debug Mode](docs/guides/debugging.md)** - Detailed request/response inspection

### SDK Capabilities

High-level features for working with the VirusTotal API:

- **Complete API Coverage** - Support for Files, URLs, Domains, IP Addresses, Analyses, and more
- **Type Safety** - Strongly typed request/response models
- **Pagination** - Automatic and manual pagination for list endpoints
- **Error Handling** - Comprehensive error types with detailed API information
- **Response Metadata** - Access to HTTP status codes, headers, timing, and body size
- **File Upload** - Support for multipart file uploads with progress callbacks
- **Context Support** - Context-aware operations for timeouts and cancellation
- **Rate Limiting** - Built-in respect for API rate limits

## Installation

```bash
go get github.com/deploymenttheory/go-api-sdk-virustotal
```

## Quick Start

Get started quickly with the SDK using the **[Quick Start Guide](docs/guides/quick-start.md)**, which includes:
- Installation instructions
- Your first API call
- Common operations (files, URLs, domains, IPs)
- Error handling patterns
- Response metadata access
- Links to configuration guides for production use

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

### VT Enterprise

- **Collections**: Manage collections of IOCs
- **Search and Metadata**: Search for IOCs and retrieve metadata

## Configuration Options

The SDK client supports extensive configuration through functional options. Below is the complete list of available configuration options grouped by category.

### Basic Configuration

```go
client.WithAPIVersion("v3")              // Set API version
client.WithBaseURL("https://...")        // Custom base URL
client.WithTimeout(30*time.Second)       // Request timeout
client.WithRetryCount(3)                 // Number of retry attempts
```

### TLS/Security

```go
client.WithMinTLSVersion(tls.VersionTLS12)                    // Minimum TLS version
client.WithTLSClientConfig(tlsConfig)                         // Custom TLS configuration
client.WithRootCertificates("/path/to/ca.pem")                // Custom CA certificates
client.WithRootCertificateFromString(caPEM)                   // CA certificate from string
client.WithClientCertificate("/path/cert.pem", "/path/key.pem") // Client certificate (mTLS)
client.WithClientCertificateFromString(certPEM, keyPEM)       // Client cert from string
client.WithInsecureSkipVerify()                               // Skip cert verification (dev only!)
```

### Network

```go
client.WithProxy("http://proxy:8080")    // HTTP/HTTPS/SOCKS5 proxy
client.WithTransport(customTransport)    // Custom HTTP transport
```

### Headers

```go
client.WithUserAgent("MyApp/1.0")                      // Set User-Agent header
client.WithCustomAgent("MyApp", "1.0")                 // Custom agent with version
client.WithGlobalHeader("X-Custom-Header", "value")    // Add single global header
client.WithGlobalHeaders(map[string]string{...})       // Add multiple global headers
```

### Observability

```go
client.WithLogger(zapLogger)            // Structured logging with zap
client.WithTracing(otelConfig)          // OpenTelemetry distributed tracing
client.WithDebug()                      // Enable debug mode (dev only!)
```

### Example: Production Configuration

```go
import (
    "crypto/tls"
    "time"
    "go.uber.org/zap"
)

logger, _ := zap.NewProduction()

apiClient, err := client.NewClient(
    "your-api-key",
    client.WithTimeout(30*time.Second),
    client.WithRetryCount(3),
    client.WithLogger(logger),
    client.WithMinTLSVersion(tls.VersionTLS12),
    client.WithGlobalHeader("X-Application-Name", "MySecurityApp"),
)
```

See the [configuration guides](docs/guides/) for detailed documentation on each option.

## Examples

The [examples directory](examples/virustotal/) contains complete working examples for all SDK features:

- **[Files](examples/virustotal/files/)** - File upload, scan, download, and report retrieval
- **[URLs](examples/virustotal/urls/)** - URL scanning and analysis
- **[Domains](examples/virustotal/domains/)** - Domain reputation and DNS lookups
- **[IP Addresses](examples/virustotal/ip_addresses/)** - IP address reputation and WHOIS
- **[Analyses](examples/virustotal/analyses/)** - Retrieve analysis results and submissions
- **[Comments](examples/virustotal/comments/)** - Manage comments on IOCs
- **[File Behaviours](examples/virustotal/file_behaviours/)** - Retrieve file behavior reports
- **[Attack Tactics](examples/virustotal/attack_tactics/)** - MITRE ATT&CK framework integration
- **[Observability](examples/virustotal/observability/)** - OpenTelemetry tracing examples

Each example includes a complete `main.go` with comments explaining the code.

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
