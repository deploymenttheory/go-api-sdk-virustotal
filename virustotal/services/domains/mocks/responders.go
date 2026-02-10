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

// DomainsMock provides mock responses for domains API endpoints
type DomainsMock struct{}

// NewDomainsMock creates a new DomainsMock instance
func NewDomainsMock() *DomainsMock {
	return &DomainsMock{}
}

// RegisterMocks registers all successful response mocks
func (m *DomainsMock) RegisterMocks() {
	m.RegisterGetDomainReportMock()
	m.RegisterRescanDomainMock()
	m.RegisterGetCommentsOnDomainMock()
	m.RegisterAddCommentToDomainMock()
	m.RegisterGetObjectDescriptorsMock()
	m.RegisterGetDNSResolutionObjectMock()
	m.RegisterGetVotesOnDomainMock()
	m.RegisterAddVoteToDomainMock()
}

// RegisterGetDomainReportMock registers the mock for GetDomainReport
func (m *DomainsMock) RegisterGetDomainReportMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/domains/example.com",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_domain_report.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterRescanDomainMock registers the mock for RescanDomain
func (m *DomainsMock) RegisterRescanDomainMock() {
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/domains/example.com/analyse",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_rescan_domain.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetCommentsOnDomainMock registers the mock for GetCommentsOnDomain
func (m *DomainsMock) RegisterGetCommentsOnDomainMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/domains/example.com/comments",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_comments.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterAddCommentToDomainMock registers the mock for AddCommentToDomain
func (m *DomainsMock) RegisterAddCommentToDomainMock() {
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/domains/example.com/comments",
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

// RegisterGetObjectDescriptorsMock registers the mock for GetObjectDescriptorsRelatedToDomain
func (m *DomainsMock) RegisterGetObjectDescriptorsMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/domains/example.com/relationships/comments",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_object_descriptors.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetDNSResolutionObjectMock registers the mock for GetDNSResolutionObject
func (m *DomainsMock) RegisterGetDNSResolutionObjectMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/resolutions/93.184.216.34-example.com",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_dns_resolution.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetVotesOnDomainMock registers the mock for GetVotesOnDomain
func (m *DomainsMock) RegisterGetVotesOnDomainMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/domains/example.com/votes",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_votes.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterAddVoteToDomainMock registers the mock for AddVoteToDomain
func (m *DomainsMock) RegisterAddVoteToDomainMock() {
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/domains/example.com/votes",
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
func (m *DomainsMock) RegisterErrorMocks() {
	m.RegisterUnauthorizedErrorMock()
	m.RegisterNotFoundErrorMock()
}

// RegisterUnauthorizedErrorMock registers the mock for unauthorized errors
func (m *DomainsMock) RegisterUnauthorizedErrorMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/domains/unauthorized",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("error_unauthorized.json")
			resp := httpmock.NewBytesResponse(401, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterNotFoundErrorMock registers the mock for not found errors
func (m *DomainsMock) RegisterNotFoundErrorMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/domains/notfound.test",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("error_not_found.json")
			resp := httpmock.NewBytesResponse(404, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// loadMockData loads a mock JSON file from the mocks directory
func (m *DomainsMock) loadMockData(filename string) []byte {
	_, currentFile, _, _ := runtime.Caller(0)
	mockDir := filepath.Dir(currentFile)
	mockPath := filepath.Join(mockDir, filename)

	data, err := os.ReadFile(mockPath)
	if err != nil {
		panic("Failed to load mock data from " + mockPath + ": " + err.Error())
	}
	return data
}
