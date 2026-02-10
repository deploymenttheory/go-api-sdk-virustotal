package mocks

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/jarcoal/httpmock"
)

// IPAddressesMock handles mock responses for IP addresses service
type IPAddressesMock struct {
	mockState []string
}

func init() {
	httpmock.RegisterNoResponder(httpmock.NewStringResponder(404, `{"error": {"code": "NotFoundError", "message": "Endpoint not found"}}`))
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
func (m *IPAddressesMock) RegisterMocks(baseURL string) {
	// GET /ip_addresses/{ip}
	mockData, err := loadMockResponse("validate_get_ip_address_report.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/ip_addresses/8.8.8.8",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/ip_addresses/8.8.8.8")
}

// RegisterErrorMocks registers all error mock responses
func (m *IPAddressesMock) RegisterErrorMocks(baseURL string) {
	// Unauthorized error
	unauthorizedData, err := loadMockResponse("error_unauthorized.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/ip_addresses/8.8.8.8",
		httpmock.NewStringResponder(401, unauthorizedData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/ip_addresses/8.8.8.8:error")

	// Not found error
	notFoundData, err := loadMockResponse("error_not_found.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/ip_addresses/999.999.999.999",
		httpmock.NewStringResponder(404, notFoundData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/ip_addresses/999.999.999.999:error")
}

// CleanupMockState clears registered mock state
func (m *IPAddressesMock) CleanupMockState() {
	m.mockState = []string{}
}
