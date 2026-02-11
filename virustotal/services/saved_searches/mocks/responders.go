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

// SavedSearchesMock provides mock responses for saved searches API endpoints
type SavedSearchesMock struct{}

// NewSavedSearchesMock creates a new SavedSearchesMock instance
func NewSavedSearchesMock() *SavedSearchesMock {
	return &SavedSearchesMock{}
}

// RegisterMocks registers all successful response mocks
func (m *SavedSearchesMock) RegisterMocks() {
	m.RegisterListSavedSearchesMock()
	m.RegisterGetSavedSearchMock()
	m.RegisterCreateSavedSearchMock()
	m.RegisterUpdateSavedSearchMock()
	m.RegisterDeleteSavedSearchMock()
	m.RegisterShareSavedSearchMock()
	m.RegisterRevokeSavedSearchAccessMock()
	m.RegisterGetObjectsRelatedToSavedSearchMock()
	m.RegisterGetObjectDescriptorsMock()
}

// RegisterListSavedSearchesMock registers the mock for ListSavedSearches
func (m *SavedSearchesMock) RegisterListSavedSearchesMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/saved_searches",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_list_saved_searches.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetSavedSearchMock registers the mock for GetSavedSearch
func (m *SavedSearchesMock) RegisterGetSavedSearchMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/saved_searches/0a49acd622a44982b1986984ba31c15b",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_saved_search.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterCreateSavedSearchMock registers the mock for CreateSavedSearch
func (m *SavedSearchesMock) RegisterCreateSavedSearchMock() {
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/saved_searches",
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

			// Check if data is provided
			data, ok := reqData["data"].(map[string]any)
			if !ok {
				return httpmock.NewStringResponse(400, `{"error": {"message": "Invalid request data"}}`), nil
			}

			// Validate attributes
			attributes, ok := data["attributes"].(map[string]any)
			if !ok {
				return httpmock.NewStringResponse(400, `{"error": {"message": "Attributes are required"}}`), nil
			}

			// Validate required fields
			if _, hasName := attributes["name"]; !hasName {
				return httpmock.NewStringResponse(400, `{"error": {"message": "Name is required"}}`), nil
			}
			if _, hasQuery := attributes["search_query"]; !hasQuery {
				return httpmock.NewStringResponse(400, `{"error": {"message": "Search query is required"}}`), nil
			}

			mockData := m.loadMockData("validate_create_saved_search.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterUpdateSavedSearchMock registers the mock for UpdateSavedSearch
func (m *SavedSearchesMock) RegisterUpdateSavedSearchMock() {
	httpmock.RegisterResponder(
		"PATCH",
		"https://www.virustotal.com/api/v3/saved_searches/0a49acd622a44982b1986984ba31c15b",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_update_saved_search.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterDeleteSavedSearchMock registers the mock for DeleteSavedSearch
func (m *SavedSearchesMock) RegisterDeleteSavedSearchMock() {
	httpmock.RegisterResponder(
		"DELETE",
		"https://www.virustotal.com/api/v3/saved_searches/0a49acd622a44982b1986984ba31c15b",
		func(req *http.Request) (*http.Response, error) {
			resp := httpmock.NewBytesResponse(200, []byte("{}"))
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterShareSavedSearchMock registers the mock for ShareSavedSearch
func (m *SavedSearchesMock) RegisterShareSavedSearchMock() {
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/saved_searches/0a49acd622a44982b1986984ba31c15b/relationship/viewers",
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

			// Check if data is provided
			data, ok := reqData["data"].([]any)
			if !ok || len(data) == 0 {
				return httpmock.NewStringResponse(400, `{"error": {"message": "At least one entity is required"}}`), nil
			}

			resp := httpmock.NewBytesResponse(200, []byte("{}"))
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)

	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/saved_searches/0a49acd622a44982b1986984ba31c15b/relationship/editors",
		func(req *http.Request) (*http.Response, error) {
			resp := httpmock.NewBytesResponse(200, []byte("{}"))
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterRevokeSavedSearchAccessMock registers the mock for RevokeSavedSearchAccess
func (m *SavedSearchesMock) RegisterRevokeSavedSearchAccessMock() {
	httpmock.RegisterResponder(
		"DELETE",
		"https://www.virustotal.com/api/v3/saved_searches/0a49acd622a44982b1986984ba31c15b/relationship/viewers",
		func(req *http.Request) (*http.Response, error) {
			resp := httpmock.NewBytesResponse(200, []byte("{}"))
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)

	httpmock.RegisterResponder(
		"DELETE",
		"https://www.virustotal.com/api/v3/saved_searches/0a49acd622a44982b1986984ba31c15b/relationship/editors",
		func(req *http.Request) (*http.Response, error) {
			resp := httpmock.NewBytesResponse(200, []byte("{}"))
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetObjectsRelatedToSavedSearchMock registers the mock for GetObjectsRelatedToSavedSearch
func (m *SavedSearchesMock) RegisterGetObjectsRelatedToSavedSearchMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/saved_searches/0a49acd622a44982b1986984ba31c15b/owner",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_related_objects.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetObjectDescriptorsMock registers the mock for GetObjectDescriptorsRelatedToSavedSearch
func (m *SavedSearchesMock) RegisterGetObjectDescriptorsMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/saved_searches/0a49acd622a44982b1986984ba31c15b/relationships/editors",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_object_descriptors.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterErrorMocks registers all error response mocks
func (m *SavedSearchesMock) RegisterErrorMocks() {
	m.RegisterUnauthorizedErrorMock()
	m.RegisterNotFoundErrorMock()
	m.RegisterForbiddenErrorMock()
	m.RegisterInvalidRequestErrorMock()
}

// RegisterUnauthorizedErrorMock registers the mock for unauthorized errors
func (m *SavedSearchesMock) RegisterUnauthorizedErrorMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/saved_searches/unauthorized",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("error_unauthorized.json")
			resp := httpmock.NewBytesResponse(401, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterNotFoundErrorMock registers the mock for not found errors
func (m *SavedSearchesMock) RegisterNotFoundErrorMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/saved_searches/00000000000000000000000000000000",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("error_not_found.json")
			resp := httpmock.NewBytesResponse(404, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterForbiddenErrorMock registers the mock for forbidden errors
func (m *SavedSearchesMock) RegisterForbiddenErrorMock() {
	httpmock.RegisterResponder(
		"DELETE",
		"https://www.virustotal.com/api/v3/saved_searches/f60631d600b44a91a8b20cef8c77aeac",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("error_forbidden.json")
			resp := httpmock.NewBytesResponse(403, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterInvalidRequestErrorMock registers the mock for invalid request errors
func (m *SavedSearchesMock) RegisterInvalidRequestErrorMock() {
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/saved_searches/invalid",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("error_invalid_request.json")
			resp := httpmock.NewBytesResponse(400, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// loadMockData loads a mock JSON file from the mocks directory
func (m *SavedSearchesMock) loadMockData(filename string) []byte {
	_, currentFile, _, _ := runtime.Caller(0)
	mockDir := filepath.Dir(currentFile)
	mockPath := filepath.Join(mockDir, filename)

	data, err := os.ReadFile(mockPath)
	if err != nil {
		panic("Failed to load mock data from " + mockPath + ": " + err.Error())
	}
	return data
}
