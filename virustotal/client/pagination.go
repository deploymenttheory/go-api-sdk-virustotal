package client

import (
	"encoding/json"
	"fmt"
	"net/url"

	"resty.dev/v3"
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

// executePaginated implements requestExecutor for Transport.
// Uses VirusTotal's cursor-based pagination via links.next.
func (t *Transport) executePaginated(req *resty.Request, path string, mergePage func([]byte) error) (*resty.Response, error) {
	var lastResp *resty.Response

	for {
		resp, err := t.executeRequest(req, "GET", path)
		lastResp = resp
		if err != nil {
			return lastResp, err
		}

		body := resp.Bytes()
		if err := mergePage(body); err != nil {
			return lastResp, err
		}

		var pageInfo struct {
			Links *PaginationLinks `json:"links,omitempty"`
		}
		if err := json.Unmarshal(body, &pageInfo); err != nil {
			return lastResp, fmt.Errorf("failed to parse pagination info: %w", err)
		}

		if !HasNextPage(pageInfo.Links) {
			break
		}

		nextParams, err := extractParamsFromURL(pageInfo.Links.Next)
		if err != nil {
			return lastResp, fmt.Errorf("failed to parse next URL: %w", err)
		}

		for k, v := range nextParams {
			req.SetQueryParam(k, v)
		}
	}

	return lastResp, nil
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
