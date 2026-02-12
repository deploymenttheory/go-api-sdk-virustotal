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
	m.RegisterGetIPAddressReportMock(baseURL)
	m.RegisterRescanIPAddressMock(baseURL)
	m.RegisterAddCommentToIPAddressMock(baseURL)
	m.RegisterGetObjectDescriptorsMock(baseURL)
	m.RegisterGetVotesOnIPAddressMock(baseURL)
	m.RegisterAddVoteToIPAddressMock(baseURL)
}

// RegisterGetIPAddressReportMock registers mock for GET /ip_addresses/{ip}
func (m *IPAddressesMock) RegisterGetIPAddressReportMock(baseURL string) {
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

// RegisterRescanIPAddressMock registers mock for POST /ip_addresses/{ip}/analyse
func (m *IPAddressesMock) RegisterRescanIPAddressMock(baseURL string) {
	mockData, err := loadMockResponse("validate_rescan_ip_address.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"POST",
		baseURL+"/ip_addresses/8.8.8.8/analyse",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "POST:"+baseURL+"/ip_addresses/8.8.8.8/analyse")
}

// RegisterAddCommentToIPAddressMock registers mock for POST /ip_addresses/{ip}/comments
func (m *IPAddressesMock) RegisterAddCommentToIPAddressMock(baseURL string) {
	mockData, err := loadMockResponse("validate_add_comment.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"POST",
		baseURL+"/ip_addresses/8.8.8.8/comments",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "POST:"+baseURL+"/ip_addresses/8.8.8.8/comments")
}

// RegisterGetObjectDescriptorsMock registers mock for GET /ip_addresses/{ip}/relationships/{relationship}
func (m *IPAddressesMock) RegisterGetObjectDescriptorsMock(baseURL string) {
	mockData, err := loadMockResponse("validate_get_object_descriptors.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/ip_addresses/8.8.8.8/relationships/comments",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/ip_addresses/8.8.8.8/relationships/comments")
}

// RegisterGetVotesOnIPAddressMock registers mock for GET /ip_addresses/{ip}/votes
func (m *IPAddressesMock) RegisterGetVotesOnIPAddressMock(baseURL string) {
	mockData, err := loadMockResponse("validate_get_votes.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/ip_addresses/8.8.8.8/votes",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/ip_addresses/8.8.8.8/votes")
}

// RegisterAddVoteToIPAddressMock registers mock for POST /ip_addresses/{ip}/votes
func (m *IPAddressesMock) RegisterAddVoteToIPAddressMock(baseURL string) {
	mockData, err := loadMockResponse("validate_add_vote.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"POST",
		baseURL+"/ip_addresses/8.8.8.8/votes",
		httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "POST:"+baseURL+"/ip_addresses/8.8.8.8/votes")
}

// RegisterErrorMocks registers all error mock responses
func (m *IPAddressesMock) RegisterErrorMocks(baseURL string) {
	m.RegisterUnauthorizedErrorMock(baseURL)
	m.RegisterNotFoundErrorMock(baseURL)
}

// RegisterUnauthorizedErrorMock registers mock for unauthorized error
func (m *IPAddressesMock) RegisterUnauthorizedErrorMock(baseURL string) {
	mockData, err := loadMockResponse("error_unauthorized.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/ip_addresses/8.8.8.8",
		httpmock.NewStringResponder(401, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/ip_addresses/8.8.8.8:error")
}

// RegisterNotFoundErrorMock registers mock for not found error
func (m *IPAddressesMock) RegisterNotFoundErrorMock(baseURL string) {
	mockData, err := loadMockResponse("error_not_found.json")
	if err != nil {
		panic(fmt.Sprintf("Failed to load mock: %v", err))
	}

	httpmock.RegisterResponder(
		"GET",
		baseURL+"/ip_addresses/999.999.999.999",
		httpmock.NewStringResponder(404, mockData).HeaderSet(http.Header{
			"Content-Type": []string{"application/json"},
		}),
	)
	m.mockState = append(m.mockState, "GET:"+baseURL+"/ip_addresses/999.999.999.999:error")
}

// RegisterRelationshipMocks registers all relationship mock responses
func (m *IPAddressesMock) RegisterRelationshipMocks(baseURL string) {
	relationships := map[string]string{
		"collections":                   "validate_relationship_collections.json",
		"comments":                      "validate_relationship_comments.json",
		"communicating_files":           "validate_relationship_communicating_files.json",
		"downloaded_files":              "validate_relationship_downloaded_files.json",
		"graphs":                        "validate_relationship_graphs.json",
		"historical_ssl_certificates":   "validate_relationship_historical_ssl_certificates.json",
		"historical_whois":              "validate_relationship_historical_whois.json",
		"related_comments":              "validate_relationship_related_comments.json",
		"related_references":            "validate_relationship_related_references.json",
		"related_threat_actors":         "validate_relationship_related_threat_actors.json",
		"referrer_files":                "validate_relationship_referrer_files.json",
		"resolutions":                   "validate_relationship_resolutions.json",
		"urls":                          "validate_relationship_urls.json",
		"user_votes":                    "validate_relationship_user_votes.json",
		"votes":                         "validate_relationship_votes.json",
	}

	for relationship, filename := range relationships {
		mockData, err := loadMockResponse(filename)
		if err != nil {
			panic(fmt.Sprintf("Failed to load mock %s: %v", filename, err))
		}

		endpoint := fmt.Sprintf("%s/ip_addresses/8.8.8.8/%s", baseURL, relationship)
		httpmock.RegisterResponder(
			"GET",
			endpoint,
			httpmock.NewStringResponder(200, mockData).HeaderSet(http.Header{
				"Content-Type": []string{"application/json"},
			}),
		)
		m.mockState = append(m.mockState, "GET:"+endpoint)
	}
}

// CleanupMockState clears registered mock state
func (m *IPAddressesMock) CleanupMockState() {
	m.mockState = []string{}
}
