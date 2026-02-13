package search_and_metadata

const (
	// Basic search endpoint - available to all users
	EndpointSearch = "/search"
	
	// VT Enterprise endpoints
	EndpointIntelligenceSearch    = "/intelligence/search"
	EndpointSearchSnippets        = "/intelligence/search/snippets"
	EndpointMetadata              = "/metadata"
)

// Search entity types
const (
	EntityTypeFile    = "file"
	EntityTypeURL     = "url"
	EntityTypeDomain  = "domain"
	EntityTypeIP      = "ip_address"
	EntityTypeComment = "comment"
)

// Sort orders for intelligence search
const (
	OrderFirstSubmissionDateAsc   = "first_submission_date+"
	OrderFirstSubmissionDateDesc  = "first_submission_date-"
	OrderLastSubmissionDateAsc    = "last_submission_date+"
	OrderLastSubmissionDateDesc   = "last_submission_date-"
	OrderPositivesAsc             = "positives+"
	OrderPositivesDesc            = "positives-"
	OrderTimesSubmittedAsc        = "times_submitted+"
	OrderTimesSubmittedDesc       = "times_submitted-"
	OrderSizeAsc                  = "size+"
	OrderSizeDesc                 = "size-"
	OrderCreationDateAsc          = "creation_date+"
	OrderCreationDateDesc         = "creation_date-"
	OrderLastModificationDateAsc  = "last_modification_date+"
	OrderLastModificationDateDesc = "last_modification_date-"
	OrderLastUpdateDateAsc        = "last_update_date+"
	OrderLastUpdateDateDesc       = "last_update_date-"
	OrderIPAsc                    = "ip+"
	OrderIPDesc                   = "ip-"
	OrderStatusAsc                = "status+"
	OrderStatusDesc               = "status-"
)
