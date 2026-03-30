package client

import (
	"fmt"

	"go.uber.org/zap"
	"resty.dev/v3"
)

// validHTTPMethods is the set of HTTP methods supported by the transport.
var validHTTPMethods = map[string]struct{}{
	"GET":    {},
	"POST":   {},
	"PUT":    {},
	"PATCH":  {},
	"DELETE": {},
	"HEAD":   {},
	"OPTIONS": {},
}

// executeRequest is a centralized request executor that handles error processing.
// Returns the resty.Response and error. Response may be non-nil even on error.
func (t *Transport) executeRequest(req *resty.Request, method, path string) (*resty.Response, error) {
	if _, ok := validHTTPMethods[method]; !ok {
		return nil, fmt.Errorf("unsupported HTTP method: %s", method)
	}

	t.logger.Debug("Executing API request",
		zap.String("method", method),
		zap.String("path", path))

	resp, err := req.Execute(method, path)
	if err != nil {
		t.logger.Error("Request failed",
			zap.String("method", method),
			zap.String("path", path),
			zap.Error(err))
		return resp, fmt.Errorf("request failed: %w", err)
	}

	if err := t.validateResponse(resp, method, path); err != nil {
		return resp, err
	}

	if resp.IsError() {
		return resp, ParseErrorResponse(
			[]byte(resp.String()),
			resp.StatusCode(),
			resp.Status(),
			method,
			path,
			t.logger,
		)
	}

	t.logger.Debug("Request completed successfully",
		zap.String("method", method),
		zap.String("path", path),
		zap.Int("status_code", resp.StatusCode()))

	return resp, nil
}

// execute implements requestExecutor for Transport.
func (t *Transport) execute(req *resty.Request, method, path string, _ any) (*resty.Response, error) {
	return t.executeRequest(req, method, path)
}

// executeGetBytes implements requestExecutor for Transport.
func (t *Transport) executeGetBytes(req *resty.Request, path string) (*resty.Response, []byte, error) {
	t.logger.Debug("Executing bytes request",
		zap.String("method", "GET"),
		zap.String("path", path))

	resp, err := req.Execute("GET", path)
	if err != nil {
		t.logger.Error("Bytes request failed",
			zap.String("path", path),
			zap.Error(err))
		return resp, nil, fmt.Errorf("bytes request failed: %w", err)
	}

	if resp.IsError() {
		return resp, nil, ParseErrorResponse(
			[]byte(resp.String()),
			resp.StatusCode(),
			resp.Status(),
			"GET",
			path,
			t.logger,
		)
	}

	body := resp.Bytes()
	t.logger.Debug("Bytes request completed successfully",
		zap.String("path", path),
		zap.Int("status_code", resp.StatusCode()),
		zap.Int("content_length", len(body)))

	return resp, body, nil
}
