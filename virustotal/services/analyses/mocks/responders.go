package mocks

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/jarcoal/httpmock"
)

// AnalysesMock handles mock responses for analyses service
type AnalysesMock struct {
	mockState []string
}

func init() {
	httpmock.RegisterNoResponder(httpmock.NewStringResponder(404, `{"error": {"code": "NotFoundError", "message": "Endpoint not found"}}`))
}

// NewAnalysesMock creates a new AnalysesMock instance
func NewAnalysesMock() *AnalysesMock {
	return &AnalysesMock{
		mockState: make([]string, 0),
	}
}

// loadMockResponse loads a mock JSON file from the mocks directory
func loadMockResponse(filename string) (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %w", err)
	}

	filePath := filepath.Join(dir, "mocks", filename)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read mock file %s: %w", filename, err)
	}

	return string(data), nil
}

// RegisterMocks registers all success mock responses
func (m *AnalysesMock) RegisterMocks(baseURL string) {
	m.RegisterGetAnalysisMock(baseURL)
	m.RegisterGetSubmissionMock(baseURL)
	m.RegisterGetOperationMock(baseURL)
	m.RegisterGetObjectsRelatedToAnalysisMock(baseURL)
	m.RegisterGetObjectDescriptorsRelatedToAnalysisMock(baseURL)
}

// RegisterGetAnalysisMock registers mock for GET /analyses/{id}
func (m *AnalysesMock) RegisterGetAnalysisMock(baseURL string) {
	mockData, err := loadMockResponse("validate_get_analysis.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/analyses/NjY0MjRlOTFjMDIyYTkyNWM0NjU2NWQzYWNlMzFmZmI6MTQ3NTA0ODI3Nw==",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/analyses/NjY0MjRlOTFjMDIyYTkyNWM0NjU2NWQzYWNlMzFmZmI6MTQ3NTA0ODI3Nw==")
}

// RegisterGetSubmissionMock registers mock for GET /submissions/{id}
func (m *AnalysesMock) RegisterGetSubmissionMock(baseURL string) {
	mockData, err := loadMockResponse("validate_get_submission.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/submissions/f-e7a2b2c164285d1203062b752d87d2f72ca9e2810b52a61f281828f28722d609-1632333331",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/submissions/f-e7a2b2c164285d1203062b752d87d2f72ca9e2810b52a61f281828f28722d609-1632333331")
}

// RegisterGetOperationMock registers mock for GET /operations/{id}
func (m *AnalysesMock) RegisterGetOperationMock(baseURL string) {
	mockData, err := loadMockResponse("validate_get_operation.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/operations/334b32b7fa5b47c78369600fad91d1b4",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/operations/334b32b7fa5b47c78369600fad91d1b4")
}

// RegisterGetObjectsRelatedToAnalysisMock registers mock for GET /analyses/{id}/{relationship}
func (m *AnalysesMock) RegisterGetObjectsRelatedToAnalysisMock(baseURL string) {
	mockData, err := loadMockResponse("validate_get_related_objects.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/analyses/test-analysis-id/item",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/analyses/test-analysis-id/item")
}

// RegisterGetObjectDescriptorsRelatedToAnalysisMock registers mock for GET /analyses/{id}/relationships/{relationship}
func (m *AnalysesMock) RegisterGetObjectDescriptorsRelatedToAnalysisMock(baseURL string) {
	mockData, err := loadMockResponse("validate_get_object_descriptors.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/analyses/test-analysis-id/relationships/item",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/analyses/test-analysis-id/relationships/item")
}

// RegisterRelationshipMocks registers all relationship endpoint mocks
func (m *AnalysesMock) RegisterRelationshipMocks() {
	baseURL := "https://www.virustotal.com/api/v3"
	analysisID := "f-1d5156ab08b6a193b8326c246847dcf14f7afcdff560729bee11b682b748ba75-1621141292"
	
	// Register item relationship mock
	mockData, err := loadMockResponse("validate_relationship_item.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}
	
	httpmock.RegisterResponder(
		"GET",
		baseURL+"/analyses/"+analysisID+"/item",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	
	// Register item relationship descriptor mock
	mockDescriptorData, err := loadMockResponse("validate_relationship_item_descriptor.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}
	
	httpmock.RegisterResponder(
		"GET",
		baseURL+"/analyses/"+analysisID+"/relationships/item",
		httpmock.NewStringResponder(200, mockDescriptorData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
}

// RegisterErrorMocks registers all error mock responses
func (m *AnalysesMock) RegisterErrorMocks(baseURL string) {
	m.RegisterUnauthorizedErrorMock(baseURL)
	m.RegisterNotFoundErrorMock(baseURL)
}

// RegisterUnauthorizedErrorMock registers mock for unauthorized error
func (m *AnalysesMock) RegisterUnauthorizedErrorMock(baseURL string) {
	mockData, err := loadMockResponse("error_unauthorized.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/analyses/invalid-id",
		httpmock.NewStringResponder(401, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/analyses/invalid-id:error")
}

// RegisterNotFoundErrorMock registers mock for not found error
func (m *AnalysesMock) RegisterNotFoundErrorMock(baseURL string) {
	mockData, err := loadMockResponse("error_not_found.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/analyses/nonexistent-id",
		httpmock.NewStringResponder(404, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/analyses/nonexistent-id:error")
}

// CleanupMockState clears registered mock state
func (m *AnalysesMock) CleanupMockState() {
	m.mockState = []string{}
}
