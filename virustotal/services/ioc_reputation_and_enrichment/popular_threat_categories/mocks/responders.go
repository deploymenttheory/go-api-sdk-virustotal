package mocks

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/jarcoal/httpmock"
)

// PopularThreatCategoriesMock handles mock responses for popular_threat_categories service
type PopularThreatCategoriesMock struct {
	mockState []string
}

func init() {
	httpmock.RegisterNoResponder(httpmock.NewStringResponder(404, `{"error": {"code": "NotFoundError", "message": "Endpoint not found"}}`))
}

// NewPopularThreatCategoriesMock creates a new PopularThreatCategoriesMock instance
func NewPopularThreatCategoriesMock() *PopularThreatCategoriesMock {
	return &PopularThreatCategoriesMock{
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
func (m *PopularThreatCategoriesMock) RegisterMocks(baseURL string) {
	m.RegisterGetPopularThreatCategoriesMock(baseURL)
}

// RegisterGetPopularThreatCategoriesMock registers mock for GET /popular_threat_categories
func (m *PopularThreatCategoriesMock) RegisterGetPopularThreatCategoriesMock(baseURL string) {
	mockData, err := loadMockResponse("validate_get_popular_threat_categories.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/popular_threat_categories",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/popular_threat_categories")
}

// RegisterErrorMocks registers all error mock responses
func (m *PopularThreatCategoriesMock) RegisterErrorMocks(baseURL string) {
	m.RegisterUnauthorizedErrorMock(baseURL)
}

// RegisterUnauthorizedErrorMock registers mock for unauthorized error
func (m *PopularThreatCategoriesMock) RegisterUnauthorizedErrorMock(baseURL string) {
	mockData, err := loadMockResponse("error_unauthorized.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/popular_threat_categories",
		httpmock.NewStringResponder(401, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/popular_threat_categories:error")
}

// CleanupMockState clears registered mock state
func (m *PopularThreatCategoriesMock) CleanupMockState() {
	m.mockState = []string{}
}
