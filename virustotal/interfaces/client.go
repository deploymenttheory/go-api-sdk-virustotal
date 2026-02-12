package interfaces

import (
	"context"
	"io"
	"time"

	"go.uber.org/zap"
)

// MultipartProgressCallback is a callback function for multipart upload progress
type MultipartProgressCallback func(fieldName string, fileName string, bytesWritten int64, totalBytes int64)

// HTTPClient interface that services will use
// This breaks import cycles by providing a contract without implementation
type HTTPClient interface {
	// Get performs an HTTP GET request and unmarshals the JSON response.
	Get(
		ctx context.Context, // request context
		path string, // API endpoint path
		queryParams map[string]string, // URL query parameters
		headers map[string]string, // HTTP headers
		result any, // pointer to unmarshal response into
	) error

	// Post sends a POST request with a JSON body and unmarshals the response.
	Post(
		ctx context.Context, // request context
		path string, // API endpoint path
		body any, // request body to marshal as JSON
		headers map[string]string, // HTTP headers
		result any, // pointer to unmarshal response into
	) error

	// PostWithQuery sends a POST request with query parameters, JSON body, and unmarshals the response.
	PostWithQuery(
		ctx context.Context, // request context
		path string, // API endpoint path
		queryParams map[string]string, // URL query parameters
		body any, // request body to marshal as JSON
		headers map[string]string, // HTTP headers
		result any, // pointer to unmarshal response into
	) error

	// PostForm sends a POST request with form-encoded data and unmarshals the response.
	PostForm(
		ctx context.Context, // request context
		path string, // API endpoint path
		formData map[string]string, // form fields as key-value pairs
		headers map[string]string, // HTTP headers
		result any, // pointer to unmarshal response into
	) error

	// PostMultipart sends a multipart/form-data POST request with file upload support.
	PostMultipart(
		ctx context.Context, // request context
		path string, // API endpoint path
		fileField string, // form field name for the file
		fileName string, // name of the file being uploaded
		fileReader io.Reader, // reader for file content
		fileSize int64, // size of the file in bytes
		formFields map[string]string, // additional form fields
		headers map[string]string, // HTTP headers
		progressCallback MultipartProgressCallback, // optional progress callback
		result any, // pointer to unmarshal response into
	) error

	// Put sends a PUT request with a JSON body and unmarshals the response.
	Put(
		ctx context.Context, // request context
		path string, // API endpoint path
		body any, // request body to marshal as JSON
		headers map[string]string, // HTTP headers
		result any, // pointer to unmarshal response into
	) error

	// Patch sends a PATCH request with a JSON body and unmarshals the response.
	Patch(
		ctx context.Context, // request context
		path string, // API endpoint path
		body any, // request body to marshal as JSON
		headers map[string]string, // HTTP headers
		result any, // pointer to unmarshal response into
	) error

	// Delete performs an HTTP DELETE request and unmarshals the response.
	Delete(
		ctx context.Context, // request context
		path string, // API endpoint path
		queryParams map[string]string, // URL query parameters
		headers map[string]string, // HTTP headers
		result any, // pointer to unmarshal response into
	) error

	// DeleteWithBody performs an HTTP DELETE request with a JSON body and unmarshals the response.
	DeleteWithBody(
		ctx context.Context, // request context
		path string, // API endpoint path
		body any, // request body to marshal as JSON
		headers map[string]string, // HTTP headers
		result any, // pointer to unmarshal response into
	) error

	// GetBytes performs an HTTP GET request and returns the raw response bytes.
	GetBytes(
		ctx context.Context, // request context
		path string, // API endpoint path
		queryParams map[string]string, // URL query parameters
		headers map[string]string, // HTTP headers
	) ([]byte, error)

	// GetLogger returns the configured zap logger instance.
	GetLogger() *zap.Logger

	// QueryBuilder returns a query builder instance for constructing URL query parameters.
	QueryBuilder() ServiceQueryBuilder

	// GetPaginated performs paginated GET requests, automatically handling pagination.
	// Calls mergePage callback for each page of results.
	GetPaginated(
		ctx context.Context, // request context
		path string, // API endpoint path
		queryParams map[string]string, // URL query parameters
		headers map[string]string, // HTTP headers
		mergePage func(pageData []byte) error, // callback to process each page
	) error
}

// ServiceQueryBuilder defines the query builder contract for services
type ServiceQueryBuilder interface {
	AddString(key, value string) QueryBuilder
	AddInt(key string, value int) QueryBuilder
	AddInt64(key string, value int64) QueryBuilder
	AddBool(key string, value bool) QueryBuilder
	AddTime(key string, value time.Time) QueryBuilder
	AddStringSlice(key string, values []string) QueryBuilder
	AddIntSlice(key string, values []int) QueryBuilder
	AddCustom(key, value string) QueryBuilder
	AddIfNotEmpty(key, value string) QueryBuilder
	AddIfTrue(condition bool, key, value string) QueryBuilder
	Merge(other map[string]string) QueryBuilder
	Remove(key string) QueryBuilder
	Has(key string) bool
	Get(key string) string
	Build() map[string]string
	BuildString() string
	Clear() QueryBuilder
	Count() int
	IsEmpty() bool
}

// QueryBuilder interface for method chaining
type QueryBuilder interface {
	ServiceQueryBuilder
}
