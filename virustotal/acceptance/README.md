# Acceptance Tests

This directory contains acceptance tests for the VirusTotal API SDK. These tests perform real API calls against the VirusTotal API and require valid API credentials.

## Prerequisites

1. **VirusTotal API Key**: You need a valid VirusTotal API key
   - Sign up at [VirusTotal](https://www.virustotal.com/)
   - Obtain your API key from your account settings

2. **Go 1.21+**: Ensure you have Go installed

## Setup

### Environment Variables

Set the following environment variables before running acceptance tests:

```bash
# Required
export VT_API_KEY="your-virustotal-api-key"

# Optional (with defaults)
export VT_BASE_URL="https://www.virustotal.com/api/v3"  # Default API endpoint
export VT_RATE_LIMIT_DELAY="2s"                          # Delay between tests
export VT_REQUEST_TIMEOUT="30s"                          # Request timeout
export VT_SKIP_CLEANUP="false"                           # Skip cleanup after tests
export VT_VERBOSE="false"                                # Enable verbose logging

# Optional test fixtures (defaults to public/safe resources)
export VT_TEST_ANALYSIS_ID="..."                         # Known analysis ID
export VT_TEST_FILE_HASH="44d88612fea8a8f36de82e1278abb02f"  # EICAR test file
export VT_TEST_DOMAIN="google.com"                       # Known domain
export VT_TEST_IP="8.8.8.8"                             # Known IP address
export VT_TEST_URL="https://www.google.com"             # Known URL
```

### Using .env File (Optional)

Create a `.env` file in the repository root (this file is gitignored):

```bash
# .env
VT_API_KEY=your-api-key-here
VT_VERBOSE=true
```

Then source it before running tests:

```bash
source .env
```

## Running Tests

### Run All Acceptance Tests

```bash
# From repository root
make test-acceptance

# Or directly with go test
go test -v ./virustotal/acceptance/...
```

### Run Specific Test

```bash
go test -v ./virustotal/acceptance/ -run TestAcceptance_Analyses_GetAnalysis
```

### Run with Verbose Output

```bash
VT_VERBOSE=true go test -v ./virustotal/acceptance/...
```

### Run Without Cleanup (for debugging)

```bash
VT_SKIP_CLEANUP=true go test -v ./virustotal/acceptance/...
```

## Test Structure

Acceptance tests follow this naming convention:

- **File naming**: `<service>_test.go` (e.g., `analyses_test.go`)
- **Test naming**: `TestAcceptance_<Service>_<Operation>` (e.g., `TestAcceptance_Analyses_GetAnalysis`)

Each test:
1. Checks if API key is set (skips if not)
2. Initializes the shared client
3. Performs real API operations
4. Validates responses
5. Implements rate limiting between tests

## Rate Limiting

VirusTotal has API rate limits based on your account tier:

- **Free**: 4 requests/minute, 500 requests/day
- **Premium**: Higher limits vary by subscription

The tests automatically implement rate limiting via `VT_RATE_LIMIT_DELAY` to avoid hitting these limits. Adjust this value based on your API tier.

## Best Practices

1. **Use Known Safe Resources**: Tests use public, safe resources (like EICAR test file, google.com) to avoid issues
2. **Respect Rate Limits**: Don't run acceptance tests in parallel without adjusting rate limits
3. **Clean Up Resources**: Tests clean up created resources unless `VT_SKIP_CLEANUP=true`
4. **Idempotent Tests**: Tests should be runnable multiple times without side effects
5. **No Secrets in Code**: Never commit API keys; always use environment variables

## CI/CD Integration

Acceptance tests can be run in GitHub Actions using repository secrets:

1. Add `VT_API_KEY` as a repository secret
2. The workflow runs on manual trigger or on a schedule (to avoid rate limit issues)

See `.github/workflows/acceptance-tests.yml` for configuration.

## Troubleshooting

### "VT_API_KEY not set, skipping acceptance test"

- **Solution**: Set the `VT_API_KEY` environment variable with your API key

### Rate Limit Errors (HTTP 429)

- **Solution**: Increase `VT_RATE_LIMIT_DELAY` (e.g., `export VT_RATE_LIMIT_DELAY="5s"`)
- **Solution**: Reduce parallel test execution

### Timeout Errors

- **Solution**: Increase `VT_REQUEST_TIMEOUT` (e.g., `export VT_REQUEST_TIMEOUT="60s"`)

### Tests Fail with 404 Not Found

- **Solution**: Verify test fixture IDs are valid in your environment
- **Solution**: Set custom test IDs via environment variables

## Adding New Acceptance Tests

1. Create a new test file: `<service>_test.go`
2. Use the helper functions from `helpers.go`
3. Follow the existing test patterns
4. Ensure tests are rate-limited
5. Add cleanup logic for created resources

Example:

```go
package acceptance

import (
    "testing"
    "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/..."
)

func TestAcceptance_NewService_Operation(t *testing.T) {
    RequireClient(t)
    
    RateLimitedTest(t, func(t *testing.T) {
        ctx, cancel := NewContext()
        defer cancel()
        
        service := newservice.NewService(Client)
        
        // Perform operation
        result, err := service.SomeOperation(ctx, ...)
        AssertNoError(t, err)
        AssertNotNil(t, result)
        
        LogResponse(t, "Operation completed successfully")
    })
}
```

## Resources

- [VirusTotal API Documentation](https://developers.virustotal.com/reference/overview)
- [API Rate Limits](https://support.virustotal.com/hc/en-us/articles/115002118525-Rate-limits)
- [EICAR Test File](https://www.eicar.org/download-anti-malware-testfile/)
