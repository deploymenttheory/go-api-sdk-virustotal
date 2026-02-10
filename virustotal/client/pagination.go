package client

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
)

// PaginationMeta contains pagination metadata for VirusTotal cursor-based pagination
type PaginationMeta struct {
	Cursor string `json:"cursor,omitempty"` // Pagination cursor for next page
	Count  int    `json:"count,omitempty"`  // Total count (if available)
}

// PaginationLinks contains pagination navigation links for VirusTotal API
type PaginationLinks struct {
	Self string `json:"self"`           // Self link
	Next string `json:"next,omitempty"` // Next page link (if available)
}

// PaginationOptions represents common pagination parameters for VirusTotal API
type PaginationOptions struct {
	Limit  int    `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}

// GetPaginated executes a paginated GET request, automatically looping through all pages.
// The mergePage callback receives raw JSON for each page and handles unmarshaling and merging.
func (c *Client) GetPaginated(ctx context.Context, path string, queryParams map[string]string, headers map[string]string, mergePage func(pageData []byte) error) error {
	currentParams := make(map[string]string)
	maps.Copy(currentParams, queryParams)

	for {
		var rawResponse json.RawMessage
		err := c.Get(ctx, path, currentParams, headers, &rawResponse)
		if err != nil {
			return err
		}

		// CRUD function handles unmarshaling and merging
		if err := mergePage(rawResponse); err != nil {
			return err
		}

		// Extract pagination info to check for next page
		var pageInfo struct {
			Links *PaginationLinks `json:"links,omitempty"`
		}
		if err := json.Unmarshal(rawResponse, &pageInfo); err != nil {
			return fmt.Errorf("failed to parse pagination info: %w", err)
		}

		// No more pages available
		if !HasNextPage(pageInfo.Links) {
			break
		}

		// Extract parameters from next page URL
		nextParams, err := extractParamsFromURL(pageInfo.Links.Next)
		if err != nil {
			return fmt.Errorf("failed to parse next URL: %w", err)
		}

		maps.Copy(currentParams, nextParams)
	}

	return nil
}

// HasNextPage checks if there is a next page available
func HasNextPage(links *PaginationLinks) bool {
	return links != nil && links.Next != ""
}

// extractParamsFromURL extracts query parameters from a URL string
func extractParamsFromURL(urlStr string) (map[string]string, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	params := make(map[string]string)
	for key, values := range parsedURL.Query() {
		if len(values) > 0 {
			params[key] = values[0]
		}
	}

	return params, nil
}
