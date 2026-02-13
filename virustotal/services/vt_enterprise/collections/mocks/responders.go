package mocks

import (
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/jarcoal/httpmock"
)

// CollectionsMock provides mock responses for Collections API endpoints
type CollectionsMock struct{}

// NewCollectionsMock creates a new CollectionsMock instance
func NewCollectionsMock() *CollectionsMock {
	return &CollectionsMock{}
}

// RegisterMocks registers all successful response mocks
func (m *CollectionsMock) RegisterMocks() {
	m.RegisterCreateCollectionMock()
	m.RegisterGetCollectionMock()
	m.RegisterUpdateCollectionMock()
	m.RegisterDeleteCollectionMock()
	m.RegisterGetCommentsOnCollectionMock()
	m.RegisterAddCommentToCollectionMock()
	m.RegisterGetObjectsRelatedToCollectionMock()
	m.RegisterGetObjectDescriptorsRelatedToCollectionMock()
	m.RegisterAddItemsToCollectionMock()
	m.RegisterDeleteItemsFromCollectionMock()
}

// RegisterCreateCollectionMock registers the mock for CreateCollection
func (m *CollectionsMock) RegisterCreateCollectionMock() {
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/collections",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_create_collection.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetCollectionMock registers the mock for GetCollection
func (m *CollectionsMock) RegisterGetCollectionMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/collections/test-collection-123",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_collection.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterUpdateCollectionMock registers the mock for UpdateCollection
func (m *CollectionsMock) RegisterUpdateCollectionMock() {
	httpmock.RegisterResponder(
		"PATCH",
		"https://www.virustotal.com/api/v3/collections/test-collection-123",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_update_collection.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterDeleteCollectionMock registers the mock for DeleteCollection
func (m *CollectionsMock) RegisterDeleteCollectionMock() {
	httpmock.RegisterResponder(
		"DELETE",
		"https://www.virustotal.com/api/v3/collections/test-collection-123",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_delete_collection.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetCommentsOnCollectionMock registers the mock for GetCommentsOnCollection
func (m *CollectionsMock) RegisterGetCommentsOnCollectionMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/collections/test-collection-123/comments",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_comments.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterAddCommentToCollectionMock registers the mock for AddCommentToCollection
func (m *CollectionsMock) RegisterAddCommentToCollectionMock() {
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/collections/test-collection-123/comments",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_add_comment.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetObjectsRelatedToCollectionMock registers the mock for GetObjectsRelatedToCollection
func (m *CollectionsMock) RegisterGetObjectsRelatedToCollectionMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/collections/test-collection-123/domains",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_related_objects.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetObjectDescriptorsRelatedToCollectionMock registers the mock for GetObjectDescriptorsRelatedToCollection
func (m *CollectionsMock) RegisterGetObjectDescriptorsRelatedToCollectionMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/collections/test-collection-123/relationships/domains",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_object_descriptors.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterAddItemsToCollectionMock registers the mock for AddItemsToCollection
func (m *CollectionsMock) RegisterAddItemsToCollectionMock() {
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/collections/test-collection-123/domains",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_add_items.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterDeleteItemsFromCollectionMock registers the mock for DeleteItemsFromCollection
func (m *CollectionsMock) RegisterDeleteItemsFromCollectionMock() {
	httpmock.RegisterResponder(
		"DELETE",
		"https://www.virustotal.com/api/v3/collections/test-collection-123/domains",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_delete_items.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterCommonErrorMocks registers common error scenarios
func (m *CollectionsMock) RegisterCommonErrorMocks() {
	// 404 Not Found
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/collections/non-existent-collection",
		func(req *http.Request) (*http.Response, error) {
			resp := httpmock.NewStringResponse(404, `{"error":{"code":"NotFoundError","message":"Collection not found"}}`)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)

	// 400 Bad Request
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/collections/invalid",
		func(req *http.Request) (*http.Response, error) {
			resp := httpmock.NewStringResponse(400, `{"error":{"code":"BadRequestError","message":"Invalid request"}}`)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)

	// 403 Forbidden (Premium feature)
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/collections/premium-collection",
		func(req *http.Request) (*http.Response, error) {
			resp := httpmock.NewStringResponse(403, `{"error":{"code":"ForbiddenError","message":"This endpoint requires a premium license"}}`)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// loadMockData loads a mock JSON file from the mocks directory
func (m *CollectionsMock) loadMockData(filename string) []byte {
	_, currentFile, _, _ := runtime.Caller(0)
	mockDir := filepath.Dir(currentFile)
	mockPath := filepath.Join(mockDir, filename)

	data, err := os.ReadFile(mockPath)
	if err != nil {
		panic("Failed to load mock data from " + mockPath + ": " + err.Error())
	}
	return data
}
