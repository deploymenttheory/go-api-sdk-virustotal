package client

import (
	"maps"
	"strconv"
	"time"
)

// queryBuilderImpl provides a fluent interface for building query parameters
type queryBuilderImpl struct {
	params map[string]string
}

// Ensure queryBuilderImpl implements the interfaces
var _ QueryBuilder = (*queryBuilderImpl)(nil)
var _ ServiceQueryBuilder = (*queryBuilderImpl)(nil)

// NewQueryBuilder creates a new query builder
func NewQueryBuilder() ServiceQueryBuilder {
	return &queryBuilderImpl{
		params: make(map[string]string),
	}
}

// AddString adds a string parameter if the value is not empty
func (qb *queryBuilderImpl) AddString(key, value string) QueryBuilder {
	if value != "" {
		qb.params[key] = value
	}
	return qb
}

// AddInt adds an integer parameter if the value is greater than 0
func (qb *queryBuilderImpl) AddInt(key string, value int) QueryBuilder {
	if value > 0 {
		qb.params[key] = strconv.Itoa(value)
	}
	return qb
}

// AddInt64 adds an int64 parameter if the value is greater than 0
func (qb *queryBuilderImpl) AddInt64(key string, value int64) QueryBuilder {
	if value > 0 {
		qb.params[key] = strconv.FormatInt(value, 10)
	}
	return qb
}

// AddBool adds a boolean parameter
func (qb *queryBuilderImpl) AddBool(key string, value bool) QueryBuilder {
	qb.params[key] = strconv.FormatBool(value)
	return qb
}

// AddTime adds a time parameter in RFC3339 format if the time is not zero
func (qb *queryBuilderImpl) AddTime(key string, value time.Time) QueryBuilder {
	if !value.IsZero() {
		qb.params[key] = value.Format(time.RFC3339)
	}
	return qb
}

// AddStringSlice adds a string slice parameter as comma-separated values
func (qb *queryBuilderImpl) AddStringSlice(key string, values []string) QueryBuilder {
	if len(values) > 0 {
		// Join multiple values with comma
		result := ""
		for i, v := range values {
			if v != "" {
				if i > 0 {
					result += ","
				}
				result += v
			}
		}
		if result != "" {
			qb.params[key] = result
		}
	}
	return qb
}

// AddIntSlice adds an integer slice parameter as comma-separated values
func (qb *queryBuilderImpl) AddIntSlice(key string, values []int) QueryBuilder {
	if len(values) > 0 {
		result := ""
		for i, v := range values {
			if i > 0 {
				result += ","
			}
			result += strconv.Itoa(v)
		}
		qb.params[key] = result
	}
	return qb
}

// AddCustom adds a custom parameter with any value
func (qb *queryBuilderImpl) AddCustom(key, value string) QueryBuilder {
	qb.params[key] = value
	return qb
}

// AddIfNotEmpty adds a parameter only if the value is not empty
func (qb *queryBuilderImpl) AddIfNotEmpty(key, value string) QueryBuilder {
	if value != "" {
		qb.params[key] = value
	}
	return qb
}

// AddIfTrue adds a parameter only if the condition is true
func (qb *queryBuilderImpl) AddIfTrue(condition bool, key, value string) QueryBuilder {
	if condition {
		qb.params[key] = value
	}
	return qb
}

// Merge merges parameters from another query builder or map
func (qb *queryBuilderImpl) Merge(other map[string]string) QueryBuilder {
	maps.Copy(qb.params, other)
	return qb
}

// Remove removes a parameter
func (qb *queryBuilderImpl) Remove(key string) QueryBuilder {
	delete(qb.params, key)
	return qb
}

// Has checks if a parameter exists
func (qb *queryBuilderImpl) Has(key string) bool {
	_, exists := qb.params[key]
	return exists
}

// Get retrieves a parameter value
func (qb *queryBuilderImpl) Get(key string) string {
	return qb.params[key]
}

// Build returns the final map of query parameters
func (qb *queryBuilderImpl) Build() map[string]string {
	// Return a copy to prevent external modification
	result := make(map[string]string, len(qb.params))
	maps.Copy(result, qb.params)
	return result
}

// BuildString returns the query parameters as a URL-encoded string
func (qb *queryBuilderImpl) BuildString() string {
	if len(qb.params) == 0 {
		return ""
	}

	result := ""
	first := true
	for k, v := range qb.params {
		if !first {
			result += "&"
		}
		result += k + "=" + v
		first = false
	}
	return result
}

// Clear removes all parameters
func (qb *queryBuilderImpl) Clear() QueryBuilder {
	qb.params = make(map[string]string)
	return qb
}

// Count returns the number of parameters
func (qb *queryBuilderImpl) Count() int {
	return len(qb.params)
}

// IsEmpty returns true if no parameters are set
func (qb *queryBuilderImpl) IsEmpty() bool {
	return len(qb.params) == 0
}
