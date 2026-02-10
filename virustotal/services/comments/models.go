package comments

// CommentVotes represents vote counts on a comment
type CommentVotes struct {
	Positive int `json:"positive"`
	Negative int `json:"negative"`
	Abuse    int `json:"abuse"`
}

// CommentAttributes represents the attributes of a comment
type CommentAttributes struct {
	Date  int64        `json:"date"`
	HTML  string       `json:"html"`
	Tags  []string     `json:"tags"`
	Text  string       `json:"text"`
	Votes CommentVotes `json:"votes"`
}

// CommentLinks represents links associated with a comment
type CommentLinks struct {
	Self string `json:"self"`
}

// CommentData represents the main comment data
type CommentData struct {
	Attributes CommentAttributes `json:"attributes"`
	ID         string            `json:"id"`
	Links      CommentLinks      `json:"links"`
	Type       string            `json:"type"`
}

// Meta represents pagination metadata
type Meta struct {
	Cursor string `json:"cursor,omitempty"`
	Count  int    `json:"count,omitempty"`
}

// Links represents pagination links
type Links struct {
	Self string `json:"self"`
	Next string `json:"next,omitempty"`
}

// =============================================================================
// Get Comments Response
// =============================================================================

// GetCommentsResponse represents the response from getting latest comments
type GetCommentsResponse struct {
	Data  []CommentData `json:"data"`
	Links Links         `json:"links"`
	Meta  Meta          `json:"meta,omitempty"`
}

// =============================================================================
// Get Comment Response
// =============================================================================

// GetCommentResponse represents the response from getting a single comment
type GetCommentResponse struct {
	Data CommentData `json:"data"`
}

// =============================================================================
// Related Objects Response
// =============================================================================

// RelatedObjectAttributes represents attributes of objects related to a comment
type RelatedObjectAttributes struct {
	Date  int64        `json:"date,omitempty"`
	HTML  string       `json:"html,omitempty"`
	Tags  []string     `json:"tags,omitempty"`
	Text  string       `json:"text,omitempty"`
	Votes CommentVotes `json:"votes,omitempty"`
}

// RelatedObject represents an object related to a comment
type RelatedObject struct {
	Attributes RelatedObjectAttributes `json:"attributes"`
	ID         string                  `json:"id"`
	Links      CommentLinks            `json:"links"`
	Type       string                  `json:"type"`
}

// RelatedObjectsResponse represents the response from getting objects related to a comment
type RelatedObjectsResponse struct {
	Data  []RelatedObject `json:"data"`
	Links Links           `json:"links"`
	Meta  Meta            `json:"meta,omitempty"`
}

// =============================================================================
// Object Descriptors Response
// =============================================================================

// ObjectDescriptor represents a lightweight object descriptor
type ObjectDescriptor struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// ObjectDescriptorsResponse represents the response from getting object descriptors
type ObjectDescriptorsResponse struct {
	Data  []ObjectDescriptor `json:"data"`
	Links Links              `json:"links"`
	Meta  Meta               `json:"meta,omitempty"`
}

// =============================================================================
// Add Vote Request/Response
// =============================================================================

// AddVoteRequest represents the request body for adding a vote to a comment
type AddVoteRequest struct {
	Data CommentVotes `json:"data"`
}

// AddVoteResponse represents the response from adding a vote to a comment
type AddVoteResponse struct {
	Data CommentVotes `json:"data"`
}

// =============================================================================
// Query Options
// =============================================================================

// GetCommentsOptions represents optional parameters for getting comments
type GetCommentsOptions struct {
	Filter string // Filter for comments (e.g., "tag:malware")
	Limit  int    // Maximum number of comments to retrieve
	Cursor string // Pagination cursor
}

// GetRelatedObjectsOptions represents optional parameters for getting related objects
type GetRelatedObjectsOptions struct {
	Limit  int    // Maximum number of objects to retrieve
	Cursor string // Pagination cursor
}
