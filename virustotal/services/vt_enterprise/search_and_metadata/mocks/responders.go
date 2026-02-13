package mocks

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/jarcoal/httpmock"
)

// SearchAndMetadataMock provides mock responses for Search & Metadata API endpoints
type SearchAndMetadataMock struct{}

// NewSearchAndMetadataMock creates a new SearchAndMetadataMock instance
func NewSearchAndMetadataMock() *SearchAndMetadataMock {
	return &SearchAndMetadataMock{}
}

// RegisterMocks registers all successful response mocks
func (m *SearchAndMetadataMock) RegisterMocks() {
	m.RegisterSearchMock()
	m.RegisterIntelligenceSearchMock()
	m.RegisterSearchSnippetsMock()
	m.RegisterMetadataMock()
}

// RegisterSearchMock registers the mock for basic Search
func (m *SearchAndMetadataMock) RegisterSearchMock() {
	httpmock.RegisterResponder(
		"GET",
		`=~^https://www\.virustotal\.com/api/v3/search\?`,
		func(req *http.Request) (*http.Response, error) {
			query := req.URL.Query().Get("query")
			if query == "" {
				return httpmock.NewStringResponse(400, `{"error": {"message": "Query parameter is required"}}`), nil
			}

			mockData := m.loadMockData("validate_search.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterIntelligenceSearchMock registers the mock for IntelligenceSearch
func (m *SearchAndMetadataMock) RegisterIntelligenceSearchMock() {
	httpmock.RegisterResponder(
		"GET",
		`=~^https://www\.virustotal\.com/api/v3/intelligence/search\?`,
		func(req *http.Request) (*http.Response, error) {
			query := req.URL.Query().Get("query")
			if query == "" {
				return httpmock.NewStringResponse(400, `{"error": {"message": "Query parameter is required"}}`), nil
			}

			mockData := m.loadMockData("validate_intelligence_search.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterSearchSnippetsMock registers the mock for GetSearchSnippets
func (m *SearchAndMetadataMock) RegisterSearchSnippetsMock() {
	httpmock.RegisterResponder(
		"GET",
		`=~^https://www\.virustotal\.com/api/v3/intelligence/search/snippets/`,
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_search_snippets.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterMetadataMock registers the mock for GetMetadata
func (m *SearchAndMetadataMock) RegisterMetadataMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/metadata",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_metadata.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// loadMockData loads a JSON mock file from the mocks directory
func (m *SearchAndMetadataMock) loadMockData(filename string) []byte {
	_, currentFile, _, _ := runtime.Caller(0)
	mocksDir := filepath.Dir(currentFile)
	filePath := filepath.Join(mocksDir, filename)

	data, err := os.ReadFile(filePath)
	if err != nil {
		panic("Failed to load mock data: " + err.Error())
	}

	return data
}

// RegisterErrorMocks registers error response mocks
func (m *SearchAndMetadataMock) RegisterErrorMocks() {
	m.RegisterUnauthorizedMock()
	m.RegisterNotFoundMock()
	m.RegisterForbiddenMock()
}

// RegisterUnauthorizedMock registers a 401 unauthorized mock
func (m *SearchAndMetadataMock) RegisterUnauthorizedMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/search?query=unauthorized",
		httpmock.NewStringResponder(401, `{"error": {"code": "AuthenticationRequiredError", "message": "Authentication is required"}}`),
	)
}

// RegisterNotFoundMock registers a 404 not found mock
func (m *SearchAndMetadataMock) RegisterNotFoundMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/search?query=notfound",
		httpmock.NewStringResponder(404, `{"error": {"code": "NotFoundError", "message": "Resource not found"}}`),
	)
}

// RegisterForbiddenMock registers a 403 forbidden mock (premium required)
func (m *SearchAndMetadataMock) RegisterForbiddenMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/intelligence/search?query=forbidden",
		httpmock.NewStringResponder(403, `{"error": {"code": "ForbiddenError", "message": "This endpoint requires premium privileges"}}`),
	)
}

// Helper function to read mock data files
func loadMockFile(filename string) []byte {
	_, currentFile, _, _ := runtime.Caller(0)
	mocksDir := filepath.Dir(currentFile)
	filePath := filepath.Join(mocksDir, filename)

	file, err := os.Open(filePath)
	if err != nil {
		panic("Failed to open mock file: " + err.Error())
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		panic("Failed to read mock file: " + err.Error())
	}

	return data
}
