package mocks

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/jarcoal/httpmock"
)

// URLsMock provides mock responses for URLs API endpoints
type URLsMock struct{}

// NewURLsMock creates a new URLsMock instance
func NewURLsMock() *URLsMock {
	return &URLsMock{}
}

// RegisterMocks registers all successful response mocks
func (m *URLsMock) RegisterMocks() {
	m.RegisterScanURLMock()
	m.RegisterGetURLReportMock()
	m.RegisterRescanURLMock()
	m.RegisterGetCommentsOnURLMock()
	m.RegisterAddCommentToURLMock()
	m.RegisterGetObjectsRelatedToURLMock()
	m.RegisterGetObjectDescriptorsMock()
	m.RegisterGetVotesOnURLMock()
	m.RegisterAddVoteToURLMock()
}

// RegisterScanURLMock registers the mock for ScanURL
func (m *URLsMock) RegisterScanURLMock() {
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/urls",
		func(req *http.Request) (*http.Response, error) {
			// Parse form data
			if err := req.ParseForm(); err != nil {
				return httpmock.NewStringResponse(400, `{"error": {"message": "Invalid form data"}}`), nil
			}

			// Check if URL is provided
			url := req.FormValue("url")
			if url == "" {
				return httpmock.NewStringResponse(400, `{"error": {"message": "URL is required"}}`), nil
			}

			mockData := m.loadMockData("validate_scan_url.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetURLReportMock registers the mock for GetURLReport
func (m *URLsMock) RegisterGetURLReportMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/urls/aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_url_report.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)

	// Also register SHA-256 variant
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/urls/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_url_report.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterRescanURLMock registers the mock for RescanURL
func (m *URLsMock) RegisterRescanURLMock() {
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/urls/aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20/analyse",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_rescan_url.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetCommentsOnURLMock registers the mock for GetCommentsOnURL
func (m *URLsMock) RegisterGetCommentsOnURLMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/urls/aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20/comments",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_comments.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterAddCommentToURLMock registers the mock for AddCommentToURL
func (m *URLsMock) RegisterAddCommentToURLMock() {
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/urls/aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20/comments",
		func(req *http.Request) (*http.Response, error) {
			// Read and validate the request body
			body, err := io.ReadAll(req.Body)
			if err != nil {
				return httpmock.NewStringResponse(400, `{"error": {"message": "Invalid request body"}}`), nil
			}

			var reqData map[string]any
			if err := json.Unmarshal(body, &reqData); err != nil {
				return httpmock.NewStringResponse(400, `{"error": {"message": "Invalid JSON"}}`), nil
			}

			// Check if comment text is provided
			data, ok := reqData["data"].(map[string]any)
			if !ok {
				return httpmock.NewBytesResponse(400, m.loadMockData("error_invalid_comment.json")), nil
			}
			attributes, ok := data["attributes"].(map[string]any)
			if !ok {
				return httpmock.NewBytesResponse(400, m.loadMockData("error_invalid_comment.json")), nil
			}
			text, ok := attributes["text"].(string)
			if !ok || text == "" {
				return httpmock.NewBytesResponse(400, m.loadMockData("error_invalid_comment.json")), nil
			}

			mockData := m.loadMockData("validate_add_comment.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetObjectsRelatedToURLMock registers the mock for GetObjectsRelatedToURL
func (m *URLsMock) RegisterGetObjectsRelatedToURLMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/urls/aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20/comments",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_comments.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetObjectDescriptorsMock registers the mock for GetObjectDescriptorsRelatedToURL
func (m *URLsMock) RegisterGetObjectDescriptorsMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/urls/aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20/relationships/comments",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_object_descriptors.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetVotesOnURLMock registers the mock for GetVotesOnURL
func (m *URLsMock) RegisterGetVotesOnURLMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/urls/aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20/votes",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_votes.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterAddVoteToURLMock registers the mock for AddVoteToURL
func (m *URLsMock) RegisterAddVoteToURLMock() {
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/urls/aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20/votes",
		func(req *http.Request) (*http.Response, error) {
			// Read and validate the request body
			body, err := io.ReadAll(req.Body)
			if err != nil {
				return httpmock.NewStringResponse(400, `{"error": {"message": "Invalid request body"}}`), nil
			}

			var reqData map[string]any
			if err := json.Unmarshal(body, &reqData); err != nil {
				return httpmock.NewStringResponse(400, `{"error": {"message": "Invalid JSON"}}`), nil
			}

			// Check if verdict is provided
			data, ok := reqData["data"].(map[string]any)
			if !ok {
				return httpmock.NewStringResponse(400, `{"error": {"message": "Invalid vote data"}}`), nil
			}
			attributes, ok := data["attributes"].(map[string]any)
			if !ok {
				return httpmock.NewStringResponse(400, `{"error": {"message": "Invalid vote attributes"}}`), nil
			}
			verdict, ok := attributes["verdict"].(string)
			if !ok || (verdict != "harmless" && verdict != "malicious") {
				return httpmock.NewStringResponse(400, `{"error": {"message": "Invalid verdict"}}`), nil
			}

			mockData := m.loadMockData("validate_add_vote.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterErrorMocks registers all error response mocks
func (m *URLsMock) RegisterErrorMocks() {
	m.RegisterUnauthorizedErrorMock()
	m.RegisterNotFoundErrorMock()
	m.RegisterInvalidURLIDErrorMock()
}

// RegisterUnauthorizedErrorMock registers the mock for unauthorized errors
func (m *URLsMock) RegisterUnauthorizedErrorMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/urls/unauthorized",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("error_unauthorized.json")
			resp := httpmock.NewBytesResponse(401, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterNotFoundErrorMock registers the mock for not found errors
func (m *URLsMock) RegisterNotFoundErrorMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/urls/aHR0cHM6Ly9ub3Rmb3VuZC50ZXN0",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("error_not_found.json")
			resp := httpmock.NewBytesResponse(404, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterInvalidURLIDErrorMock registers the mock for invalid URL ID errors
func (m *URLsMock) RegisterInvalidURLIDErrorMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/urls/invalid+id",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("error_invalid_url_id.json")
			resp := httpmock.NewBytesResponse(400, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// loadMockData loads a mock JSON file from the mocks directory
func (m *URLsMock) loadMockData(filename string) []byte {
	_, currentFile, _, _ := runtime.Caller(0)
	mockDir := filepath.Dir(currentFile)
	mockPath := filepath.Join(mockDir, filename)

	data, err := os.ReadFile(mockPath)
	if err != nil {
		panic("Failed to load mock data from " + mockPath + ": " + err.Error())
	}
	return data
}
