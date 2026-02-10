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

// FilesMock provides mock responses for files API endpoints
type FilesMock struct{}

// NewFilesMock creates a new FilesMock instance
func NewFilesMock() *FilesMock {
	return &FilesMock{}
}

// RegisterMocks registers all successful response mocks
func (m *FilesMock) RegisterMocks() {
	m.RegisterUploadFileMock()
	m.RegisterGetUploadURLMock()
	m.RegisterGetFileReportMock()
	m.RegisterRescanFileMock()
	m.RegisterGetDownloadURLMock()
	m.RegisterDownloadFileMock()
	m.RegisterGetCommentsOnFileMock()
	m.RegisterAddCommentToFileMock()
	m.RegisterGetObjectsRelatedToFileMock()
	m.RegisterGetObjectDescriptorsRelatedToFileMock()
	m.RegisterGetSigmaRuleMock()
	m.RegisterGetYARARulesetMock()
	m.RegisterGetVotesOnFileMock()
	m.RegisterAddVoteToFileMock()
}

// RegisterErrorMocks registers all error response mocks
func (m *FilesMock) RegisterErrorMocks() {
	m.RegisterUnauthorizedErrorMock()
	m.RegisterNotFoundErrorMock()
	m.RegisterInvalidCommentErrorMock()
}

// RegisterUploadFileMock registers the mock for UploadFile
func (m *FilesMock) RegisterUploadFileMock() {
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/files",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_upload_file.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetUploadURLMock registers the mock for GetUploadURL
func (m *FilesMock) RegisterGetUploadURLMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/files/upload_url",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_upload_url.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetFileReportMock registers the mock for GetFileReport
func (m *FilesMock) RegisterGetFileReportMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_file_report.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterRescanFileMock registers the mock for RescanFile
func (m *FilesMock) RegisterRescanFileMock() {
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f/analyse",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_rescan_file.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetDownloadURLMock registers the mock for GetFileDownloadURL
func (m *FilesMock) RegisterGetDownloadURLMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f/download_url",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_download_url.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterDownloadFileMock registers the mock for DownloadFile
func (m *FilesMock) RegisterDownloadFileMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f/download",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_download_url.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetCommentsOnFileMock registers the mock for GetCommentsOnFile
func (m *FilesMock) RegisterGetCommentsOnFileMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f/comments",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_comments.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterAddCommentToFileMock registers the mock for AddCommentToFile
func (m *FilesMock) RegisterAddCommentToFileMock() {
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f/comments",
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

// RegisterGetObjectsRelatedToFileMock registers the mock for GetObjectsRelatedToFile
func (m *FilesMock) RegisterGetObjectsRelatedToFileMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f/contacted_domains",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_related_objects.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetObjectDescriptorsRelatedToFileMock registers the mock for GetObjectDescriptorsRelatedToFile
func (m *FilesMock) RegisterGetObjectDescriptorsRelatedToFileMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f/relationships/contacted_domains",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_object_descriptors.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetSigmaRuleMock registers the mock for GetSigmaRule
func (m *FilesMock) RegisterGetSigmaRuleMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/sigma_rules/sigma-rule-123",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_sigma_rule.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetYARARulesetMock registers the mock for GetYARARuleset
func (m *FilesMock) RegisterGetYARARulesetMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/yara_rulesets/yara-ruleset-123",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_yara_ruleset.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterGetVotesOnFileMock registers the mock for GetVotesOnFile
func (m *FilesMock) RegisterGetVotesOnFileMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f/votes",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("validate_get_votes.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterAddVoteToFileMock registers the mock for AddVoteToFile
func (m *FilesMock) RegisterAddVoteToFileMock() {
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f/votes",
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

// RegisterUnauthorizedErrorMock registers the mock for unauthorized errors
func (m *FilesMock) RegisterUnauthorizedErrorMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/files/unauthorized",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("error_unauthorized.json")
			resp := httpmock.NewBytesResponse(401, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterNotFoundErrorMock registers the mock for not found errors
func (m *FilesMock) RegisterNotFoundErrorMock() {
	httpmock.RegisterResponder(
		"GET",
		"https://www.virustotal.com/api/v3/files/notfound",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("error_not_found.json")
			resp := httpmock.NewBytesResponse(404, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterInvalidCommentErrorMock registers the mock for invalid comment errors
func (m *FilesMock) RegisterInvalidCommentErrorMock() {
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f/comments/invalid",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("error_invalid_comment.json")
			resp := httpmock.NewBytesResponse(400, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// loadMockData loads a mock JSON file from the mocks directory
func (m *FilesMock) loadMockData(filename string) []byte {
	_, currentFile, _, _ := runtime.Caller(0)
	mockDir := filepath.Dir(currentFile)
	mockPath := filepath.Join(mockDir, filename)

	data, err := os.ReadFile(mockPath)
	if err != nil {
		panic("Failed to load mock data from " + mockPath + ": " + err.Error())
	}
	return data
}
