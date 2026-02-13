# Authentication

## What is API Key Authentication?

The VirusTotal SDK uses API key authentication to securely access the VirusTotal API. Your API key is sent with every request in the `x-apikey` header to identify and authorize your application.

## Why Use Proper Authentication?

Proper authentication handling helps you:

- **Secure your credentials** - Avoid hardcoding API keys in source code
- **Prevent unauthorized access** - Ensure only valid API keys are used
- **Enable key rotation** - Easily update keys without code changes
- **Support multiple environments** - Use different keys for dev, staging, and production
- **Audit usage** - Track which keys are making requests

## When to Use It

Always use proper authentication when:

- Accessing the VirusTotal API from any application
- Deploying to production environments
- Sharing code in version control systems
- Running automated tests or CI/CD pipelines
- Managing multiple VirusTotal accounts or API tiers

## Basic Example

Here's the recommended way to authenticate with the VirusTotal SDK:

```go
package main

import (
    "context"
    "log"
    "os"

    "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"
    "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/services/ioc_reputation_and_enrichment/files"
)

func main() {
    // Step 1: Get API key from environment variable (recommended)
    apiKey := os.Getenv("VT_API_KEY")
    if apiKey == "" {
        log.Fatal("VT_API_KEY environment variable is required")
    }

    // Step 2: Create client with API key
    vtClient, err := client.NewClient(apiKey)
    if err != nil {
        log.Fatal(err)
    }

    // Step 3: Use the client - authentication is automatic
    filesService := files.NewService(vtClient)
    result, _, err := filesService.GetFileReport(
        context.Background(),
        "44d88612fea8a8f36de82e1278abb02f",
    )
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("File: %s", result.Data.Attributes.MeaningfulName)
}
```

**Run the example:**

```bash
export VT_API_KEY="your-api-key-here"
go run main.go
```

## Alternative Configuration Options

### Option 1: Environment Variables (Recommended)

Store API keys in environment variables for security and flexibility:

```go
// Production: Read from environment
apiKey := os.Getenv("VT_API_KEY")

vtClient, err := client.NewClient(apiKey)
```

**When to use:** Always in production. This is the most secure approach.

**Setup:**
```bash
# Linux/macOS
export VT_API_KEY="your-api-key"

# Windows PowerShell
$env:VT_API_KEY="your-api-key"

# Docker
docker run -e VT_API_KEY="your-api-key" myapp

# Kubernetes Secret
kubectl create secret generic vt-credentials --from-literal=api-key="your-api-key"
```

---

### Option 2: Configuration Files

Load API keys from configuration files (not committed to version control):

```go
package main

import (
    "encoding/json"
    "os"
)

type Config struct {
    APIKey string `json:"api_key"`
}

func loadConfig(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    var config Config
    if err := json.Unmarshal(data, &config); err != nil {
        return nil, err
    }

    return &config, nil
}

func main() {
    // Load from config file
    config, err := loadConfig("config.json")
    if err != nil {
        log.Fatal(err)
    }

    vtClient, err := client.NewClient(config.APIKey)
    // ... use client
}
```

**config.json:**
```json
{
  "api_key": "your-api-key-here"
}
```

**When to use:** Development environments where you need per-developer configuration.

**.gitignore:**
```
config.json
*.local.json
```

---

### Option 3: Secret Management Services

Use dedicated secret management services for enterprise deployments:

**AWS Secrets Manager:**
```go
import (
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/secretsmanager"
)

func getAPIKeyFromAWS() (string, error) {
    sess := session.Must(session.NewSession())
    svc := secretsmanager.New(sess)

    result, err := svc.GetSecretValue(&secretsmanager.GetSecretValueInput{
        SecretId: aws.String("virustotal/api-key"),
    })
    if err != nil {
        return "", err
    }

    return *result.SecretString, nil
}

func main() {
    apiKey, err := getAPIKeyFromAWS()
    if err != nil {
        log.Fatal(err)
    }

    vtClient, err := client.NewClient(apiKey)
    // ... use client
}
```

**HashiCorp Vault:**
```go
import "github.com/hashicorp/vault/api"

func getAPIKeyFromVault() (string, error) {
    vaultClient, err := api.NewClient(api.DefaultConfig())
    if err != nil {
        return "", err
    }

    secret, err := vaultClient.Logical().Read("secret/data/virustotal")
    if err != nil {
        return "", err
    }

    apiKey := secret.Data["data"].(map[string]interface{})["api_key"].(string)
    return apiKey, nil
}
```

**When to use:** Production environments with compliance requirements or centralized secret management.

---

### Option 4: Multiple API Keys

Use different API keys for different purposes or rate limits:

```go
package main

type VirusTotalService struct {
    publicClient  *client.Client
    premiumClient *client.Client
}

func NewVirusTotalService() (*VirusTotalService, error) {
    // Public API (free tier)
    publicClient, err := client.NewClient(
        os.Getenv("VT_PUBLIC_API_KEY"),
    )
    if err != nil {
        return nil, err
    }

    // Premium API (higher limits)
    premiumClient, err := client.NewClient(
        os.Getenv("VT_PREMIUM_API_KEY"),
    )
    if err != nil {
        return nil, err
    }

    return &VirusTotalService{
        publicClient:  publicClient,
        premiumClient: premiumClient,
    }, nil
}

func (s *VirusTotalService) ScanFile(ctx context.Context, hash string, usePremium bool) {
    // Choose client based on requirements
    var c *client.Client
    if usePremium {
        c = s.premiumClient
    } else {
        c = s.publicClient
    }

    filesService := files.NewService(c)
    // ... use service
}
```

**When to use:** When you have multiple API keys with different rate limits or permissions.

---

## Security Best Practices

### ✅ Do:

- Store API keys in environment variables
- Use secret management services in production
- Rotate API keys regularly
- Use different keys for different environments
- Revoke compromised keys immediately
- Add `*.env` files to `.gitignore`

### ❌ Don't:

- Hardcode API keys in source code
- Commit API keys to version control
- Share API keys in plaintext (email, chat, etc.)
- Use production keys in development
- Log API keys in application logs
- Store API keys in client-side code

## Troubleshooting

### Authentication Failed (401 Unauthorized)

**Symptoms:** `WrongCredentialsError` or `AuthenticationRequiredError`

**Solutions:**
```go
import "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"

// Check for authentication errors
if err != nil && client.IsUnauthorized(err) {
    log.Println("Invalid API key - check your credentials")
}

// Or check specific error codes
if err != nil && client.IsWrongCredentials(err) {
    log.Println("API key is incorrect")
}
```

**Common causes:**
- Invalid or expired API key
- API key not set in environment variable
- Typo in the API key
- Using wrong key for the environment

### Rate Limiting (429 Too Many Requests)

**Symptoms:** `QuotaExceededError` or `TooManyRequestsError`

**Solution:**
```go
if err != nil && client.IsQuotaExceeded(err) {
    log.Println("Rate limit exceeded - wait before retrying")
    time.Sleep(60 * time.Second)
}
```

See [Rate Limiting Guide](rate-limiting.md) for more details.

## Testing with Authentication

### Unit Tests

Mock the client to avoid real API calls:

```go
func TestMyFunction(t *testing.T) {
    // Use a mock/test API key
    testClient, _ := client.NewClient("test-api-key")

    // Configure mock HTTP responses
    // ... your test code
}
```

### Acceptance Tests

Use a dedicated test API key:

```bash
# Set test API key
export VT_TEST_API_KEY="your-test-key"

# Run acceptance tests
go test -tags=acceptance ./...
```

## Related Documentation

- [Error Handling](error-handling.md) - Handle authentication errors
- [Rate Limiting](rate-limiting.md) - Understand API quotas
- [Timeouts & Retries](timeouts-retries.md) - Configure retry logic for auth errors
- [VirusTotal API Keys](https://support.virustotal.com/hc/en-us/articles/115002088769-Please-give-me-an-API-key)
