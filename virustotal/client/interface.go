package client

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// Client is the interface service implementations depend on.
type Client interface {
	NewRequest(ctx context.Context) *RequestBuilder
	QueryBuilder() ServiceQueryBuilder
	GetLogger() *zap.Logger
}

// ServiceQueryBuilder defines the query builder contract for services.
// Provides a fluent interface for constructing URL query parameters.
type ServiceQueryBuilder interface {
	// AddString adds a string parameter if the value is not empty.
	// Returns the builder for method chaining.
	AddString(key, value string) QueryBuilder

	// AddInt adds an integer parameter if the value is greater than 0.
	// The integer is converted to a string representation.
	// Returns the builder for method chaining.
	AddInt(key string, value int) QueryBuilder

	// AddInt64 adds an int64 parameter if the value is greater than 0.
	// The int64 is converted to a string representation.
	// Returns the builder for method chaining.
	AddInt64(key string, value int64) QueryBuilder

	// AddBool adds a boolean parameter.
	// The boolean is converted to "true" or "false" string representation.
	// Returns the builder for method chaining.
	AddBool(key string, value bool) QueryBuilder

	// AddTime adds a time parameter in RFC3339 format if the time is not zero.
	// Returns the builder for method chaining.
	AddTime(key string, value time.Time) QueryBuilder

	// AddStringSlice adds a string slice parameter as comma-separated values.
	// Empty string values within the slice are skipped.
	// Returns the builder for method chaining.
	AddStringSlice(key string, values []string) QueryBuilder

	// AddIntSlice adds an integer slice parameter as comma-separated values.
	// Returns the builder for method chaining.
	AddIntSlice(key string, values []int) QueryBuilder

	// AddCustom adds a custom parameter with any value without validation.
	// Use this when you need to add a parameter regardless of its value.
	// Returns the builder for method chaining.
	AddCustom(key, value string) QueryBuilder

	// AddIfNotEmpty adds a parameter only if the value is not empty.
	// Functionally equivalent to AddString.
	// Returns the builder for method chaining.
	AddIfNotEmpty(key, value string) QueryBuilder

	// AddIfTrue adds a parameter only if the condition is true.
	// Returns the builder for method chaining.
	AddIfTrue(condition bool, key, value string) QueryBuilder

	// Merge copies all parameters from another map into this builder.
	// Existing parameters with the same keys will be overwritten.
	// Returns the builder for method chaining.
	Merge(other map[string]string) QueryBuilder

	// Remove deletes a parameter from the builder.
	// Returns the builder for method chaining.
	Remove(key string) QueryBuilder

	// Has checks if a parameter exists in the builder.
	Has(key string) bool

	// Get retrieves the value of a parameter.
	// Returns an empty string if the parameter does not exist.
	Get(key string) string

	// Build returns a copy of the query parameters as a map.
	// The returned map is a copy to prevent external modification.
	Build() map[string]string

	// BuildString returns the query parameters as a URL-encoded string.
	// Parameters are joined with "&" separators in key=value format.
	// Returns an empty string if no parameters are set.
	BuildString() string

	// Clear removes all parameters from the builder.
	// Returns the builder for method chaining.
	Clear() QueryBuilder

	// Count returns the number of parameters currently in the builder.
	Count() int

	// IsEmpty returns true if no parameters are set in the builder.
	IsEmpty() bool
}

// QueryBuilder interface for method chaining.
// Embeds ServiceQueryBuilder to provide the same functionality.
type QueryBuilder interface {
	ServiceQueryBuilder
}
