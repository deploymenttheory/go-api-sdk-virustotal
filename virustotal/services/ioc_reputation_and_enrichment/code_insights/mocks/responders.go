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

// CodeInsightsMock provides mock responses for code insights API endpoints
type CodeInsightsMock struct{}

// NewCodeInsightsMock creates a new CodeInsightsMock instance
func NewCodeInsightsMock() *CodeInsightsMock {
	return &CodeInsightsMock{}
}

// RegisterMocks registers all successful response mocks
func (m *CodeInsightsMock) RegisterMocks() {
	m.RegisterAnalyseCodeMock()
	m.RegisterAnalyseCodeWithHistoryMock()
}

// RegisterAnalyseCodeMock registers the mock for AnalyseCode
func (m *CodeInsightsMock) RegisterAnalyseCodeMock() {
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/codeinsights/analyse-binary",
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

			// Validate code field
			code, hasCode := data["code"].(string)
			if !hasCode || code == "" {
				return httpmock.NewStringResponse(400, `{"error": {"message": "code field is required"}}`), nil
			}

			// Validate code_type field
			codeType, hasCodeType := data["code_type"].(string)
			if !hasCodeType || codeType == "" {
				return httpmock.NewStringResponse(400, `{"error": {"message": "code_type field is required"}}`), nil
			}

			// Check if code_type is valid
			if codeType != "disassembled" && codeType != "decompiled" {
				return httpmock.NewStringResponse(400, `{"error": {"message": "code_type must be 'disassembled' or 'decompiled'"}}`), nil
			}

			// Check if history is provided
			history, hasHistory := data["history"]
			if hasHistory && history != nil {
				mockData := m.loadMockData("validate_analyse_code_with_history.json")
				resp := httpmock.NewBytesResponse(200, mockData)
				resp.Header.Set("Content-Type", "application/json")
				return resp, nil
			}

			mockData := m.loadMockData("validate_analyse_code.json")
			resp := httpmock.NewBytesResponse(200, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterAnalyseCodeWithHistoryMock registers the mock for AnalyseCode with history
func (m *CodeInsightsMock) RegisterAnalyseCodeWithHistoryMock() {
	// This is handled by RegisterAnalyseCodeMock with history detection
}

// RegisterErrorMocks registers all error response mocks
func (m *CodeInsightsMock) RegisterErrorMocks() {
	m.RegisterUnauthorizedErrorMock()
	m.RegisterInvalidRequestErrorMock()
	m.RegisterRateLimitErrorMock()
}

// RegisterUnauthorizedErrorMock registers the mock for unauthorized errors
func (m *CodeInsightsMock) RegisterUnauthorizedErrorMock() {
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/codeinsights/analyse-binary/unauthorized",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("error_unauthorized.json")
			resp := httpmock.NewBytesResponse(401, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterInvalidRequestErrorMock registers the mock for invalid request errors
func (m *CodeInsightsMock) RegisterInvalidRequestErrorMock() {
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/codeinsights/analyse-binary/invalid",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("error_invalid_request.json")
			resp := httpmock.NewBytesResponse(400, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// RegisterRateLimitErrorMock registers the mock for rate limit errors
func (m *CodeInsightsMock) RegisterRateLimitErrorMock() {
	httpmock.RegisterResponder(
		"POST",
		"https://www.virustotal.com/api/v3/codeinsights/analyse-binary/ratelimit",
		func(req *http.Request) (*http.Response, error) {
			mockData := m.loadMockData("error_rate_limit.json")
			resp := httpmock.NewBytesResponse(429, mockData)
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	)
}

// loadMockData loads a mock JSON file from the mocks directory
func (m *CodeInsightsMock) loadMockData(filename string) []byte {
	_, currentFile, _, _ := runtime.Caller(0)
	mockDir := filepath.Dir(currentFile)
	mockPath := filepath.Join(mockDir, filename)

	data, err := os.ReadFile(mockPath)
	if err != nil {
		panic("Failed to load mock data from " + mockPath + ": " + err.Error())
	}
	return data
}
