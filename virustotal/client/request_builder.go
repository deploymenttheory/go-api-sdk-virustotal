package client

import (
	"io"

	"resty.dev/v3"
)

// MultipartProgressCallback is a callback function for multipart upload progress.
type MultipartProgressCallback func(fieldName string, fileName string, bytesWritten int64, totalBytes int64)

// requestExecutor is the internal interface implemented by Transport that RequestBuilder delegates to.
type requestExecutor interface {
	execute(req *resty.Request, method, path string, result any) (*resty.Response, error)
	executeGetBytes(req *resty.Request, path string) (*resty.Response, []byte, error)
	executePaginated(req *resty.Request, path string, mergePage func([]byte) error) (*resty.Response, error)
}

// RequestBuilder provides a fluent builder for constructing and executing HTTP requests.
type RequestBuilder struct {
	req      *resty.Request
	executor requestExecutor
}

// SetHeader sets a header on the request.
func (b *RequestBuilder) SetHeader(key, value string) *RequestBuilder {
	b.req.SetHeader(key, value)
	return b
}

// SetQueryParam sets a query parameter on the request.
func (b *RequestBuilder) SetQueryParam(key, value string) *RequestBuilder {
	b.req.SetQueryParam(key, value)
	return b
}

// SetBody sets the request body.
func (b *RequestBuilder) SetBody(body any) *RequestBuilder {
	b.req.SetBody(body)
	return b
}

// SetResult sets the result pointer for JSON unmarshaling.
func (b *RequestBuilder) SetResult(result any) *RequestBuilder {
	b.req.SetResult(result)
	return b
}

// SetFormData sets form-urlencoded data for the request.
func (b *RequestBuilder) SetFormData(data map[string]string) *RequestBuilder {
	b.req.SetFormData(data)
	return b
}

// SetMultipartFile sets a multipart file field with optional progress callback.
func (b *RequestBuilder) SetMultipartFile(fieldName, fileName string, reader io.Reader, fileSize int64, progressCallback MultipartProgressCallback) *RequestBuilder {
	if reader != nil && fileName != "" && fieldName != "" {
		multipartField := &resty.MultipartField{
			Name:     fieldName,
			FileName: fileName,
			Reader:   reader,
			FileSize: fileSize,
		}

		if progressCallback != nil {
			multipartField.ProgressCallback = func(progress resty.MultipartFieldProgress) {
				progressCallback(progress.Name, progress.FileName, progress.Written, progress.FileSize)
			}
		}

		b.req.SetMultipartFields(multipartField)
	}
	return b
}

// SetMultipartFormData sets additional form fields for multipart requests.
func (b *RequestBuilder) SetMultipartFormData(data map[string]string) *RequestBuilder {
	if len(data) > 0 {
		b.req.SetMultipartFormData(data)
	}
	return b
}

// Get executes a GET request to the given path.
func (b *RequestBuilder) Get(path string) (*resty.Response, error) {
	return b.executor.execute(b.req, "GET", path, nil)
}

// Post executes a POST request to the given path.
func (b *RequestBuilder) Post(path string) (*resty.Response, error) {
	return b.executor.execute(b.req, "POST", path, nil)
}

// Put executes a PUT request to the given path.
func (b *RequestBuilder) Put(path string) (*resty.Response, error) {
	return b.executor.execute(b.req, "PUT", path, nil)
}

// Patch executes a PATCH request to the given path.
func (b *RequestBuilder) Patch(path string) (*resty.Response, error) {
	return b.executor.execute(b.req, "PATCH", path, nil)
}

// Delete executes a DELETE request to the given path.
func (b *RequestBuilder) Delete(path string) (*resty.Response, error) {
	return b.executor.execute(b.req, "DELETE", path, nil)
}

// GetBytes executes a GET request and returns the raw response bytes without JSON unmarshaling.
func (b *RequestBuilder) GetBytes(path string) (*resty.Response, []byte, error) {
	return b.executor.executeGetBytes(b.req, path)
}

// GetPaginated executes a paginated GET request, automatically looping through all pages.
// The mergePage callback receives raw JSON bytes for each page.
func (b *RequestBuilder) GetPaginated(path string, mergePage func([]byte) error) (*resty.Response, error) {
	return b.executor.executePaginated(b.req, path, mergePage)
}

// NewMockRequestBuilder creates a RequestBuilder backed by a mock executor for testing.
func NewMockRequestBuilder(req *resty.Request, exec requestExecutor) *RequestBuilder {
	return &RequestBuilder{req: req, executor: exec}
}

// NewMockRequestBuilderWithQueryCapture creates a RequestBuilder that captures the resty.Request for assertion in tests.
func NewMockRequestBuilderWithQueryCapture(req *resty.Request, exec requestExecutor) (*RequestBuilder, *resty.Request) {
	rb := &RequestBuilder{req: req, executor: exec}
	return rb, req
}
