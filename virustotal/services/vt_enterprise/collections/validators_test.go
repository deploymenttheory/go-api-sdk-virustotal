package collections

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// ValidateCollectionID Tests
// =============================================================================

func TestValidateCollectionID(t *testing.T) {
	tests := []struct {
		name        string
		collectionID string
		expectError bool
	}{
		{
			name:         "Valid collection ID",
			collectionID: "test-collection-123",
			expectError:  false,
		},
		{
			name:         "Empty collection ID",
			collectionID: "",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCollectionID(tt.collectionID)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "collection ID cannot be empty")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// =============================================================================
// ValidateCollectionName Tests
// =============================================================================

func TestValidateCollectionName(t *testing.T) {
	tests := []struct {
		name        string
		collectionName string
		expectError bool
	}{
		{
			name:           "Valid collection name",
			collectionName: "Test Collection",
			expectError:    false,
		},
		{
			name:           "Empty collection name",
			collectionName: "",
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCollectionName(tt.collectionName)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "collection name cannot be empty")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// =============================================================================
// ValidateCreateCollectionRequest Tests
// =============================================================================

func TestValidateCreateCollectionRequest(t *testing.T) {
	tests := []struct {
		name        string
		request     *CreateCollectionRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid request with relationships",
			request: &CreateCollectionRequest{
				Data: CreateCollectionData{
					Type: "collection",
					Attributes: CreateCollectionAttributes{
						Name:        "Test Collection",
						Description: "Test description",
					},
					Relationships: &CollectionRelationships{
						Domains: &RelationshipData{
							Data: []RelationshipItem{
								{Type: "domain", ID: "virustotal.com"},
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "Valid request with raw items",
			request: &CreateCollectionRequest{
				Data: CreateCollectionData{
					Type: "collection",
					Attributes: CreateCollectionAttributes{
						Name: "Test Collection",
					},
					RawItems: "virustotal.com",
				},
			},
			expectError: false,
		},
		{
			name:        "Nil request",
			request:     nil,
			expectError: true,
			errorMsg:    "create collection request cannot be nil",
		},
		{
			name: "Invalid type",
			request: &CreateCollectionRequest{
				Data: CreateCollectionData{
					Type: "invalid",
					Attributes: CreateCollectionAttributes{
						Name: "Test",
					},
					RawItems: "test",
				},
			},
			expectError: true,
			errorMsg:    "invalid collection type",
		},
		{
			name: "Empty name",
			request: &CreateCollectionRequest{
				Data: CreateCollectionData{
					Type: "collection",
					Attributes: CreateCollectionAttributes{
						Name: "",
					},
					RawItems: "test",
				},
			},
			expectError: true,
			errorMsg:    "collection name cannot be empty",
		},
		{
			name: "No relationships or raw items",
			request: &CreateCollectionRequest{
				Data: CreateCollectionData{
					Type: "collection",
					Attributes: CreateCollectionAttributes{
						Name: "Test",
					},
				},
			},
			expectError: true,
			errorMsg:    "either relationships or raw_items must be provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCreateCollectionRequest(tt.request)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// =============================================================================
// ValidateUpdateCollectionRequest Tests
// =============================================================================

func TestValidateUpdateCollectionRequest(t *testing.T) {
	tests := []struct {
		name        string
		request     *UpdateCollectionRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid request with attributes",
			request: &UpdateCollectionRequest{
				Data: UpdateCollectionData{
					Type: "collection",
					Attributes: &UpdateCollectionAttributes{
						Name: "Updated Name",
					},
				},
			},
			expectError: false,
		},
		{
			name: "Valid request with raw items",
			request: &UpdateCollectionRequest{
				Data: UpdateCollectionData{
					Type:     "collection",
					RawItems: "new items",
				},
			},
			expectError: false,
		},
		{
			name:        "Nil request",
			request:     nil,
			expectError: true,
			errorMsg:    "update collection request cannot be nil",
		},
		{
			name: "Invalid type",
			request: &UpdateCollectionRequest{
				Data: UpdateCollectionData{
					Type:     "invalid",
					RawItems: "test",
				},
			},
			expectError: true,
			errorMsg:    "invalid collection type",
		},
		{
			name: "No fields to update",
			request: &UpdateCollectionRequest{
				Data: UpdateCollectionData{
					Type: "collection",
				},
			},
			expectError: true,
			errorMsg:    "at least one field must be provided for update",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUpdateCollectionRequest(tt.request)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// =============================================================================
// ValidateRelationship Tests
// =============================================================================

func TestValidateRelationship(t *testing.T) {
	tests := []struct {
		name         string
		relationship string
		expectError  bool
	}{
		{
			name:         "Valid relationship - domains",
			relationship: RelationshipDomains,
			expectError:  false,
		},
		{
			name:         "Valid relationship - files",
			relationship: RelationshipFiles,
			expectError:  false,
		},
		{
			name:         "Valid relationship - ip_addresses",
			relationship: RelationshipIPAddresses,
			expectError:  false,
		},
		{
			name:         "Empty relationship",
			relationship: "",
			expectError:  true,
		},
		{
			name:         "Invalid relationship",
			relationship: "invalid_relationship",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRelationship(tt.relationship)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// =============================================================================
// ValidateAddItemsRequest Tests
// =============================================================================

func TestValidateAddItemsRequest(t *testing.T) {
	tests := []struct {
		name        string
		request     *AddItemsRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid request with domain",
			request: &AddItemsRequest{
				Data: []RelationshipItem{
					{Type: "domain", ID: "virustotal.com"},
				},
			},
			expectError: false,
		},
		{
			name: "Valid request with URL using ID",
			request: &AddItemsRequest{
				Data: []RelationshipItem{
					{Type: "url", ID: "abc123"},
				},
			},
			expectError: false,
		},
		{
			name: "Valid request with URL using URL field",
			request: &AddItemsRequest{
				Data: []RelationshipItem{
					{Type: "url", URL: "https://virustotal.com"},
				},
			},
			expectError: false,
		},
		{
			name:        "Nil request",
			request:     nil,
			expectError: true,
			errorMsg:    "add items request cannot be nil",
		},
		{
			name: "Empty items list",
			request: &AddItemsRequest{
				Data: []RelationshipItem{},
			},
			expectError: true,
			errorMsg:    "items list cannot be empty",
		},
		{
			name: "Item without type",
			request: &AddItemsRequest{
				Data: []RelationshipItem{
					{ID: "test"},
				},
			},
			expectError: true,
			errorMsg:    "type cannot be empty",
		},
		{
			name: "Non-URL item without ID",
			request: &AddItemsRequest{
				Data: []RelationshipItem{
					{Type: "domain"},
				},
			},
			expectError: true,
			errorMsg:    "ID cannot be empty",
		},
		{
			name: "URL item without ID or URL",
			request: &AddItemsRequest{
				Data: []RelationshipItem{
					{Type: "url"},
				},
			},
			expectError: true,
			errorMsg:    "either ID or URL must be provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAddItemsRequest(tt.request)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// =============================================================================
// ValidateDeleteItemsRequest Tests
// =============================================================================

func TestValidateDeleteItemsRequest(t *testing.T) {
	tests := []struct {
		name        string
		request     *DeleteItemsRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid request",
			request: &DeleteItemsRequest{
				Data: []RelationshipItem{
					{Type: "domain", ID: "virustotal.com"},
				},
			},
			expectError: false,
		},
		{
			name:        "Nil request",
			request:     nil,
			expectError: true,
			errorMsg:    "delete items request cannot be nil",
		},
		{
			name: "Empty items list",
			request: &DeleteItemsRequest{
				Data: []RelationshipItem{},
			},
			expectError: true,
			errorMsg:    "items list cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDeleteItemsRequest(tt.request)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// =============================================================================
// ValidateCommentText Tests
// =============================================================================

func TestValidateCommentText(t *testing.T) {
	tests := []struct {
		name        string
		text        string
		expectError bool
	}{
		{
			name:        "Valid comment text",
			text:        "This is a test comment",
			expectError: false,
		},
		{
			name:        "Empty comment text",
			text:        "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCommentText(tt.text)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "comment text cannot be empty")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// =============================================================================
// ValidateAddCommentRequest Tests
// =============================================================================

func TestValidateAddCommentRequest(t *testing.T) {
	tests := []struct {
		name        string
		request     *AddCommentRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid request",
			request: &AddCommentRequest{
				Data: AddCommentData{
					Type: "comment",
					Attributes: AddCommentAttributes{
						Text: "Test comment",
					},
				},
			},
			expectError: false,
		},
		{
			name:        "Nil request",
			request:     nil,
			expectError: true,
			errorMsg:    "add comment request cannot be nil",
		},
		{
			name: "Invalid type",
			request: &AddCommentRequest{
				Data: AddCommentData{
					Type: "invalid",
					Attributes: AddCommentAttributes{
						Text: "Test",
					},
				},
			},
			expectError: true,
			errorMsg:    "invalid comment type",
		},
		{
			name: "Empty comment text",
			request: &AddCommentRequest{
				Data: AddCommentData{
					Type: "comment",
					Attributes: AddCommentAttributes{
						Text: "",
					},
				},
			},
			expectError: true,
			errorMsg:    "comment text cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAddCommentRequest(tt.request)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
