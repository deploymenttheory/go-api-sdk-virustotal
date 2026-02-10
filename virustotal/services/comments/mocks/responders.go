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

// CommentsMock provides mock responses for comments API endpoints
type CommentsMock struct{}

// NewCommentsMock creates a new CommentsMock instance
func NewCommentsMock() *CommentsMock {
	return &CommentsMock{}
}

// RegisterMocks registers all successful response mocks
func (m *CommentsMock) RegisterMocks() {
	m.RegisterGetLatestCommentsMock()
	m.RegisterGetCommentMock()
	m.RegisterDeleteCommentMock()
	m.RegisterGetObjectsRelatedToCommentMock()
	m.RegisterGetObjectDescriptorsMock()
	m.RegisterAddVoteToCommentMock()
}

// RegisterGetLatestCommentsMock registers the mock for GetLatestComments
func (m *CommentsMock) RegisterGetLatestCommentsMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/comments",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_latest_comments.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetCommentMock registers the mock for GetComment
func (m *CommentsMock) RegisterGetCommentMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/comments/u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_comment.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterDeleteCommentMock registers the mock for DeleteComment
func (m *CommentsMock) RegisterDeleteCommentMock() {
	httpmock.RegisterResponder(
		"DELETE",
		"https://www.virustotal.com/api/v3/comments/u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345",
		func(req *http.Request) (*http.Response, error) {
			resp := httpmock.NewBytesResponse(200, []byte("{}"))
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetObjectsRelatedToCommentMock registers the mock for GetObjectsRelatedToComment
func (m *CommentsMock) RegisterGetObjectsRelatedToCommentMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/comments/u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345/author",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_related_objects.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetObjectDescriptorsMock registers the mock for GetObjectDescriptorsRelatedToComment
func (m *CommentsMock) RegisterGetObjectDescriptorsMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/comments/u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345/relationships/author",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_object_descriptors.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterAddVoteToCommentMock registers the mock for AddVoteToComment
func (m *CommentsMock) RegisterAddVoteToCommentMock() {
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/comments/u-aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20-abc12345/vote",
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

			// Check if vote data is provided
			data, ok := reqData["data"].(map[string]any)
			if !ok {
				return httpmock.NewStringResponse(400, `{"error": {"message": "Invalid vote data"}}`), nil
			}

			// Validate that at least one vote field exists
			_, hasPositive := data["positive"]
			_, hasNegative := data["negative"]
			_, hasAbuse := data["abuse"]

			if !hasPositive && !hasNegative && !hasAbuse {
				return httpmock.NewStringResponse(400, `{"error": {"message": "At least one vote field required"}}`), nil
			}

			mockData := m.loadMockData("validate_add_vote.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterErrorMocks registers all error response mocks
func (m *CommentsMock) RegisterErrorMocks() {
	m.RegisterUnauthorizedErrorMock()
	m.RegisterNotFoundErrorMock()
	m.RegisterInvalidCommentIDErrorMock()
}

// RegisterUnauthorizedErrorMock registers the mock for unauthorized errors
func (m *CommentsMock) RegisterUnauthorizedErrorMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/comments/unauthorized",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("error_unauthorized.json")
			resp := httpmock.NewBytesResponse(401, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterNotFoundErrorMock registers the mock for not found errors
func (m *CommentsMock) RegisterNotFoundErrorMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/comments/d-notfound.test-abc123",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("error_not_found.json")
			resp := httpmock.NewBytesResponse(404, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterInvalidCommentIDErrorMock registers the mock for invalid comment ID errors
func (m *CommentsMock) RegisterInvalidCommentIDErrorMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/comments/invalid-id",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("error_invalid_comment_id.json")
			resp := httpmock.NewBytesResponse(400, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// loadMockData loads a mock JSON file from the mocks directory
func (m *CommentsMock) loadMockData(filename string) []byte {
	_, currentFile, _, _ := runtime.Caller(0)
	mockDir := filepath.Dir(currentFile)
	mockPath := filepath.Join(mockDir, filename)

	data, err := os.ReadFile(mockPath)
	if err != nil {
		panic("Failed to load mock data from " + mockPath + ": " + err.Error())
	}
	return data
}
