// Package client provides a Go client for the Delegator API.
//
// The client abstracts HTTP communication with the delegator service and provides
// methods that correspond to the onboarding workflow: DID verification, FQDN
// verification, proof submission, and status checking.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/storacha/delegator/internal/models"
)

// Client represents a delegator API client.
type Client struct {
	httpClient *http.Client
	baseURL    string
	userAgent  string
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) {
		c.httpClient = client
	}
}

// WithTimeout sets the HTTP client timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

// WithUserAgent sets a custom user agent.
func WithUserAgent(userAgent string) Option {
	return func(c *Client) {
		c.userAgent = userAgent
	}
}

// New creates a new delegator API client.
func New(baseURL string, opts ...Option) (*Client, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("base URL cannot be empty")
	}

	// Validate and normalize base URL
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	if u.Scheme == "" {
		u.Scheme = "http"
	}

	c := &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL:   strings.TrimSuffix(u.String(), "/"),
		userAgent: "delegator-client/1.0",
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

// HealthCheck checks if the delegator service is healthy.
func (c *Client) HealthCheck(ctx context.Context) error {
	req, err := c.newRequest(ctx, http.MethodGet, "/health", nil)
	if err != nil {
		return fmt.Errorf("creating health check request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("service unhealthy: status %d", resp.StatusCode)
	}

	return nil
}

// RegisterDID registers a DID and initiates the onboarding process.
// Returns the session ID and delegation download URL.
func (c *Client) RegisterDID(ctx context.Context, did string) (*models.DIDVerifyResponse, error) {
	return c.RegisterDIDWithOptions(ctx, did, "", 0, "")
}

// RegisterDIDWithOptions registers a DID with additional information and initiates the onboarding process.
// Returns the session ID and delegation download URL.
func (c *Client) RegisterDIDWithOptions(ctx context.Context, did string, filecoinAddress string, proofSetID uint64, operatorEmail string) (*models.DIDVerifyResponse, error) {
	if did == "" {
		return nil, fmt.Errorf("DID cannot be empty")
	}

	req := models.DIDRegisterRequest{
		DID:             did,
		FilecoinAddress: filecoinAddress,
		ProofSetID:      proofSetID,
		OperatorEmail:   operatorEmail,
	}

	var resp models.DIDVerifyResponse
	if err := c.doRequest(ctx, http.MethodPost, "/api/v1/onboard/register-did", req, &resp); err != nil {
		return nil, fmt.Errorf("registering DID: %w", err)
	}

	return &resp, nil
}

// RegisterFQDN registers and verifies an FQDN for the given session.
func (c *Client) RegisterFQDN(ctx context.Context, sessionID, fqdnURL string) (*models.FQDNVerifyResponse, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session ID cannot be empty")
	}
	if fqdnURL == "" {
		return nil, fmt.Errorf("FQDN URL cannot be empty")
	}

	req := models.FQDNRegisterRequest{
		SessionID: sessionID,
		URL:       fqdnURL,
	}

	var resp models.FQDNVerifyResponse
	if err := c.doRequest(ctx, http.MethodPost, "/api/v1/onboard/register-fqdn", req, &resp); err != nil {
		return nil, fmt.Errorf("registering FQDN: %w", err)
	}

	return &resp, nil
}

// TestStorage tests the storage capabilities (blob/allocate and blob/accept) for the given session.
func (c *Client) TestStorage(ctx context.Context, sessionID string) (*models.StorageTestResponse, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session ID cannot be empty")
	}

	req := models.StorageTestRequest{
		SessionID: sessionID,
	}

	var resp models.StorageTestResponse
	if err := c.doRequest(ctx, http.MethodPost, "/api/v1/onboard/test-storage", req, &resp); err != nil {
		return nil, fmt.Errorf("testing storage: %w", err)
	}

	return &resp, nil
}

// RegisterProof submits a proof delegation to complete the onboarding process.
func (c *Client) RegisterProof(ctx context.Context, sessionID, proof string) (*models.ProofVerifyResponse, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session ID cannot be empty")
	}
	if proof == "" {
		return nil, fmt.Errorf("proof cannot be empty")
	}

	req := models.ProofRegisterRequest{
		SessionID: sessionID,
		Proof:     proof,
	}

	var resp models.ProofVerifyResponse
	if err := c.doRequest(ctx, http.MethodPost, "/api/v1/onboard/register-proof", req, &resp); err != nil {
		return nil, fmt.Errorf("registering proof: %w", err)
	}

	return &resp, nil
}

// GetStatus retrieves the status of an onboarding session.
func (c *Client) GetStatus(ctx context.Context, sessionID string) (*models.OnboardingStatusResponse, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session ID cannot be empty")
	}

	endpoint := fmt.Sprintf("/api/v1/onboard/status/%s", sessionID)

	var resp models.OnboardingStatusResponse
	if err := c.doRequest(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return nil, fmt.Errorf("getting session status: %w", err)
	}

	return &resp, nil
}

// DownloadDelegation downloads the delegation file for a session.
// Returns the delegation content as bytes.
func (c *Client) DownloadDelegation(ctx context.Context, sessionID string) ([]byte, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session ID cannot be empty")
	}

	endpoint := fmt.Sprintf("/api/v1/onboard/delegation/%s", sessionID)

	req, err := c.newRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating delegation download request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading delegation: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading delegation content: %w", err)
	}

	return data, nil
}

// doRequest performs an HTTP request with JSON serialization/deserialization.
func (c *Client) doRequest(ctx context.Context, method, endpoint string, body interface{}, result interface{}) error {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshaling request body: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := c.newRequest(ctx, method, endpoint, reqBody)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return c.handleErrorResponse(resp)
	}

	// For successful responses, decode into the API response wrapper
	var apiResp models.APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	if !apiResp.Success {
		return fmt.Errorf("API error: %s", apiResp.Error)
	}

	// Re-marshal and unmarshal to convert the data to the expected type
	if result != nil && apiResp.Data != nil {
		data, err := json.Marshal(apiResp.Data)
		if err != nil {
			return fmt.Errorf("marshaling response data: %w", err)
		}

		if err := json.Unmarshal(data, result); err != nil {
			return fmt.Errorf("unmarshaling response data: %w", err)
		}
	}

	return nil
}

// newRequest creates a new HTTP request with common headers.
func (c *Client) newRequest(ctx context.Context, method, endpoint string, body io.Reader) (*http.Request, error) {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing base URL: %w", err)
	}
	u.Path = path.Join(u.Path, endpoint)

	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	return req, nil
}

// handleErrorResponse processes error responses from the API.
func (c *Client) handleErrorResponse(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)

	// Try to decode as error response
	var errResp models.ErrorResponse
	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
		return &APIError{
			StatusCode: resp.StatusCode,
			Message:    errResp.Message,
			ErrorCode:  errResp.Error,
		}
	}

	// Try to decode as API response with error
	var apiResp models.APIResponse
	if err := json.Unmarshal(body, &apiResp); err == nil && !apiResp.Success {
		return &APIError{
			StatusCode: resp.StatusCode,
			Message:    apiResp.Message,
			ErrorCode:  apiResp.Error,
		}
	}

	// Fallback to raw response
	return &APIError{
		StatusCode: resp.StatusCode,
		Message:    string(body),
		ErrorCode:  fmt.Sprintf("HTTP_%d", resp.StatusCode),
	}
}

// APIError represents an error response from the delegator API.
type APIError struct {
	StatusCode int    `json:"status_code"`
	Message    string `json:"message"`
	ErrorCode  string `json:"error_code"`
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("delegator API error (%d): %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("delegator API error (%d): %s", e.StatusCode, e.ErrorCode)
}

// IsNotFound returns true if the error is a 404 Not Found.
func (e *APIError) IsNotFound() bool {
	return e.StatusCode == http.StatusNotFound
}

// IsBadRequest returns true if the error is a 400 Bad Request.
func (e *APIError) IsBadRequest() bool {
	return e.StatusCode == http.StatusBadRequest
}

// IsForbidden returns true if the error is a 403 Forbidden.
func (e *APIError) IsForbidden() bool {
	return e.StatusCode == http.StatusForbidden
}

// IsConflict returns true if the error is a 409 Conflict.
func (e *APIError) IsConflict() bool {
	return e.StatusCode == http.StatusConflict
}
