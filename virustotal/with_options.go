package virustotal

import "github.com/deploymenttheory/go-api-sdk-virustotal/virustotal/client"

// ClientOption re-exports client.ClientOption for use without importing the client package.
type ClientOption = client.ClientOption

// OTelConfig re-exports client.OTelConfig for use without importing the client package.
type OTelConfig = client.OTelConfig

// Re-export all With* functions so examples only need to import the virustotal package.
var (
	WithBaseURL                     = client.WithBaseURL
	WithAPIVersion                  = client.WithAPIVersion
	WithAPIKey                      = client.WithAPIKey
	WithTimeout                     = client.WithTimeout
	WithRetryCount                  = client.WithRetryCount
	WithRetryWaitTime               = client.WithRetryWaitTime
	WithRetryMaxWaitTime            = client.WithRetryMaxWaitTime
	WithLogger                      = client.WithLogger
	WithDebug                       = client.WithDebug
	WithUserAgent                   = client.WithUserAgent
	WithCustomAgent                 = client.WithCustomAgent
	WithGlobalHeader                = client.WithGlobalHeader
	WithGlobalHeaders               = client.WithGlobalHeaders
	WithProxy                       = client.WithProxy
	WithTLSClientConfig             = client.WithTLSClientConfig
	WithClientCertificate           = client.WithClientCertificate
	WithClientCertificateFromString = client.WithClientCertificateFromString
	WithRootCertificates            = client.WithRootCertificates
	WithRootCertificateFromString   = client.WithRootCertificateFromString
	WithTransport                   = client.WithTransport
	WithInsecureSkipVerify          = client.WithInsecureSkipVerify
	WithMinTLSVersion               = client.WithMinTLSVersion
	WithTracing                     = client.WithTracing
)
