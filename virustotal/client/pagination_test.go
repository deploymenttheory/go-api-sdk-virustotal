package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"resty.dev/v3"
)

func TestHasNextPage(t *testing.T) {
	tests := []struct {
		name     string
		links    *PaginationLinks
		expected bool
	}{
		{
			name:     "nil links",
			links:    nil,
			expected: false,
		},
		{
			name:     "empty next link",
			links:    &PaginationLinks{Self: "https://api.example.com/v3/files", Next: ""},
			expected: false,
		},
		{
			name:     "valid next link",
			links:    &PaginationLinks{Self: "https://api.example.com/v3/files", Next: "https://api.example.com/v3/files?cursor=abc123"},
			expected: true,
		},
		{
			name:     "only self link",
			links:    &PaginationLinks{Self: "https://api.example.com/v3/files"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasNextPage(tt.links)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractParamsFromURL(t *testing.T) {
	tests := []struct {
		name        string
		urlStr      string
		expected    map[string]string
		expectError bool
	}{
		{
			name:   "valid URL with single param",
			urlStr: "https://api.example.com/v3/files?cursor=abc123",
			expected: map[string]string{
				"cursor": "abc123",
			},
			expectError: false,
		},
		{
			name:   "valid URL with multiple params",
			urlStr: "https://api.example.com/v3/files?cursor=abc123&limit=10&filter=malicious",
			expected: map[string]string{
				"cursor": "abc123",
				"limit":  "10",
				"filter": "malicious",
			},
			expectError: false,
		},
		{
			name:        "URL with no params",
			urlStr:      "https://api.example.com/v3/files",
			expected:    map[string]string{},
			expectError: false,
		},
		{
			name:        "invalid URL",
			urlStr:      "://invalid-url",
			expected:    nil,
			expectError: true,
		},
		{
			name:   "URL with encoded params",
			urlStr: "https://api.example.com/v3/files?filter=has%20malware&cursor=xyz789",
			expected: map[string]string{
				"filter": "has malware",
				"cursor": "xyz789",
			},
			expectError: false,
		},
		{
			name:   "URL with duplicate param (takes first)",
			urlStr: "https://api.example.com/v3/files?cursor=first&cursor=second",
			expected: map[string]string{
				"cursor": "first",
			},
			expectError: false,
		},
		{
			name:        "empty URL",
			urlStr:      "",
			expected:    map[string]string{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := extractParamsFromURL(tt.urlStr)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func newTestTransport(t *testing.T, serverURL string) *Transport {
	t.Helper()
	logger := zaptest.NewLogger(t)
	return &Transport{
		client: resty.New().SetBaseURL(serverURL),
		logger: logger,
		authConfig: &AuthConfig{
			APIKey:     "test-key",
			APIVersion: "v3",
		},
		globalHeaders: make(map[string]string),
	}
}

func TestGetPaginated_SinglePage(t *testing.T) {
	// Create a test server that returns a single page
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]any{
			"data": []map[string]string{
				{"id": "file1", "type": "file"},
				{"id": "file2", "type": "file"},
			},
			"links": map[string]string{
				"self": "https://api.example.com/v3/files",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	transport := newTestTransport(t, server.URL)

	// Track pages received
	pageCount := 0
	var allData []map[string]string

	mergePage := func(pageData []byte) error {
		pageCount++
		var page struct {
			Data []map[string]string `json:"data"`
		}
		if err := json.Unmarshal(pageData, &page); err != nil {
			return err
		}
		allData = append(allData, page.Data...)
		return nil
	}

	ctx := context.Background()
	resp, err := transport.NewRequest(ctx).GetPaginated("/files", mergePage)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, 1, pageCount, "Should process exactly 1 page")
	assert.Len(t, allData, 2, "Should have 2 items total")
}

func TestGetPaginated_MultiplePages(t *testing.T) {
	currentPage := 0
	pages := []map[string]any{
		{
			"data": []map[string]string{
				{"id": "file1", "type": "file"},
				{"id": "file2", "type": "file"},
			},
			"links": map[string]string{
				"self": "https://api.example.com/v3/files",
				"next": "https://api.example.com/v3/files?cursor=page2",
			},
		},
		{
			"data": []map[string]string{
				{"id": "file3", "type": "file"},
				{"id": "file4", "type": "file"},
			},
			"links": map[string]string{
				"self": "https://api.example.com/v3/files?cursor=page2",
				"next": "https://api.example.com/v3/files?cursor=page3",
			},
		},
		{
			"data": []map[string]string{
				{"id": "file5", "type": "file"},
			},
			"links": map[string]string{
				"self": "https://api.example.com/v3/files?cursor=page3",
			},
		},
	}

	// Create a test server that returns multiple pages
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if currentPage >= len(pages) {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(pages[currentPage])
		currentPage++
	}))
	defer server.Close()

	transport := newTestTransport(t, server.URL)

	// Track pages received
	pageCount := 0
	var allData []map[string]string

	mergePage := func(pageData []byte) error {
		pageCount++
		var page struct {
			Data []map[string]string `json:"data"`
		}
		if err := json.Unmarshal(pageData, &page); err != nil {
			return err
		}
		allData = append(allData, page.Data...)
		return nil
	}

	ctx := context.Background()
	resp, err := transport.NewRequest(ctx).GetPaginated("/files", mergePage)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, 3, pageCount, "Should process exactly 3 pages")
	assert.Len(t, allData, 5, "Should have 5 items total across all pages")

	// Verify all IDs are present
	ids := make([]string, len(allData))
	for i, item := range allData {
		ids[i] = item["id"]
	}
	assert.Contains(t, ids, "file1")
	assert.Contains(t, ids, "file2")
	assert.Contains(t, ids, "file3")
	assert.Contains(t, ids, "file4")
	assert.Contains(t, ids, "file5")
}

func TestGetPaginated_WithInitialQueryParams(t *testing.T) {
	requestCount := 0

	// Create a test server that validates query params
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		// Verify initial query params are preserved
		limit := r.URL.Query().Get("limit")
		assert.Equal(t, "10", limit, "Limit param should be preserved")

		response := map[string]any{
			"data": []map[string]string{
				{"id": fmt.Sprintf("file%d", requestCount), "type": "file"},
			},
			"links": map[string]string{
				"self": r.URL.String(),
			},
		}

		// Only first request has next page
		if requestCount == 1 {
			response["links"].(map[string]string)["next"] = fmt.Sprintf("http://%s/files?cursor=page2&limit=10", r.Host)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	transport := newTestTransport(t, server.URL)

	mergePage := func(pageData []byte) error {
		return nil
	}

	ctx := context.Background()
	resp, err := transport.NewRequest(ctx).
		SetQueryParam("limit", "10").
		GetPaginated("/files", mergePage)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, 2, requestCount, "Should make 2 requests")
}

func TestGetPaginated_MergePageError(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]any{
			"data": []map[string]string{{"id": "file1"}},
			"links": map[string]string{
				"self": "https://api.example.com/v3/files",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	transport := newTestTransport(t, server.URL)

	// mergePage that returns an error
	mergePage := func(pageData []byte) error {
		return fmt.Errorf("merge failed")
	}

	ctx := context.Background()
	resp, err := transport.NewRequest(ctx).GetPaginated("/files", mergePage)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "merge failed")
	assert.NotNil(t, resp, "Response should still be returned even on error")
}

func TestGetPaginated_HTTPError(t *testing.T) {
	// Create a test server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": {"message": "Invalid API key"}}`))
	}))
	defer server.Close()

	transport := newTestTransport(t, server.URL)

	mergePage := func(pageData []byte) error {
		return nil
	}

	ctx := context.Background()
	resp, err := transport.NewRequest(ctx).GetPaginated("/files", mergePage)

	require.Error(t, err)
	assert.NotNil(t, resp, "Response should be returned even on error")
}

func TestGetPaginated_InvalidNextURL(t *testing.T) {
	// Create a test server that returns an invalid next URL
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]any{
			"data": []map[string]string{{"id": "file1"}},
			"links": map[string]string{
				"self": "https://api.example.com/v3/files",
				"next": "://invalid-url",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	transport := newTestTransport(t, server.URL)

	pageCount := 0
	mergePage := func(pageData []byte) error {
		pageCount++
		return nil
	}

	ctx := context.Background()
	resp, err := transport.NewRequest(ctx).GetPaginated("/files", mergePage)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse next URL")
	assert.Equal(t, 1, pageCount, "Should have processed first page before error")
	assert.NotNil(t, resp)
}

func TestPaginationTypes(t *testing.T) {
	t.Run("PaginationMeta", func(t *testing.T) {
		meta := PaginationMeta{
			Cursor: "abc123",
			Count:  100,
		}

		data, err := json.Marshal(meta)
		require.NoError(t, err)

		var unmarshaled PaginationMeta
		err = json.Unmarshal(data, &unmarshaled)
		require.NoError(t, err)

		assert.Equal(t, meta.Cursor, unmarshaled.Cursor)
		assert.Equal(t, meta.Count, unmarshaled.Count)
	})

	t.Run("PaginationLinks", func(t *testing.T) {
		links := PaginationLinks{
			Self: "https://api.example.com/v3/files",
			Next: "https://api.example.com/v3/files?cursor=abc123",
		}

		data, err := json.Marshal(links)
		require.NoError(t, err)

		var unmarshaled PaginationLinks
		err = json.Unmarshal(data, &unmarshaled)
		require.NoError(t, err)

		assert.Equal(t, links.Self, unmarshaled.Self)
		assert.Equal(t, links.Next, unmarshaled.Next)
	})

	t.Run("PaginationOptions", func(t *testing.T) {
		opts := PaginationOptions{
			Limit:  10,
			Cursor: "xyz789",
		}

		data, err := json.Marshal(opts)
		require.NoError(t, err)

		var unmarshaled PaginationOptions
		err = json.Unmarshal(data, &unmarshaled)
		require.NoError(t, err)

		assert.Equal(t, opts.Limit, unmarshaled.Limit)
		assert.Equal(t, opts.Cursor, unmarshaled.Cursor)
	})
}
