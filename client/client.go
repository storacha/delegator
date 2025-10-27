package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
}

func New(baseURL string) (*Client, error) {
	_, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

func (c *Client) WithHTTPClient(httpClient *http.Client) *Client {
	c.httpClient = httpClient
	return c
}

type RequestApprovalRequest struct {
	Operator     string `json:"operator"`
	OwnerAddress string `json:"owner_address"`
	Signature    []byte `json:"signature"`
}

func (c *Client) RequestApproval(ctx context.Context, req *RequestApprovalRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/registrar/request-approval", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		var errResp map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil {
			if errMsg, ok := errResp["error"]; ok {
				return fmt.Errorf("registration failed: %s", errMsg)
			}
		}
		return fmt.Errorf("registration failed with status: %d", resp.StatusCode)
	}

	return nil
}

type RegisterRequest struct {
	Operator      string `json:"operator"`
	OwnerAddress  string `json:"owner_address"`
	ProofSetID    uint64 `json:"proof_set_id"`
	OperatorEmail string `json:"operator_email"`
	PublicURL     string `json:"public_url"`
	Proof         string `json:"proof"`
}

func (c *Client) Register(ctx context.Context, req *RegisterRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/registrar/register-node", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var errResp map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil {
			if errMsg, ok := errResp["error"]; ok {
				return fmt.Errorf("registration failed: %s", errMsg)
			}
		}
		return fmt.Errorf("registration failed with status: %d", resp.StatusCode)
	}

	return nil
}

type IsRegisteredRequest struct {
	DID string `json:"did"`
}

func (c *Client) IsRegistered(ctx context.Context, req *IsRegisteredRequest) (bool, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return false, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/registrar/is-registered", bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return false, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		var errResp map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil {
			if errMsg, ok := errResp["error"]; ok {
				return false, fmt.Errorf("check registration failed: %s", errMsg)
			}
		}
		return false, fmt.Errorf("check registration failed with status: %d", resp.StatusCode)
	}
}

type RequestProofsRequest struct {
	DID string `json:"did"`
}

type RequestProofsResponse struct {
	Proofs Proofs `json:"proofs"`
}

type Proofs struct {
	Indexer       string `json:"indexer"`
	EgressTracker string `json:"egress_tracker"`
}

func (c *Client) RequestProofs(ctx context.Context, did string) (*RequestProofsResponse, error) {
	req := &RequestProofsRequest{DID: did}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/registrar/request-proofs", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil {
			if errMsg, ok := errResp["error"]; ok {
				return nil, fmt.Errorf("request proof failed: %s", errMsg)
			}
		}
		return nil, fmt.Errorf("request proof failed with status: %d", resp.StatusCode)
	}

	var result RequestProofsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

func (c *Client) HealthCheck(ctx context.Context) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed with status: %d", resp.StatusCode)
	}

	return nil
}

type BenchmarkUploadRequest struct {
	OperatorDID      string `json:"operator_did"`
	OperatorEndpoint string `json:"operator_endpoint"`
	OperatorProof    string `json:"operator_proof"`
	Size             int64  `json:"size"`
}

type BenchmarkUploadResponse struct {
	AllocateDuration string `json:"allocate_duration"`
	UploadDuration   string `json:"upload_duration"`
	AcceptDuration   string `json:"accept_duration"`
	DownloadURL      string `json:"download_url,omitempty"`
	PieceLink        string `json:"piece_link,omitempty"`
}

func (c *Client) BenchmarkUpload(ctx context.Context, req *BenchmarkUploadRequest) (*BenchmarkUploadResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/benchmark/upload", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil {
			if errMsg, ok := errResp["error"]; ok {
				return nil, fmt.Errorf("benchmark upload failed: %s", errMsg)
			}
		}
		return nil, fmt.Errorf("benchmark upload failed with status: %d", resp.StatusCode)
	}

	var result BenchmarkUploadResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

type BenchmarkDownloadRequest struct {
	Endpoint string `json:"endpoint"`
}

type BenchmarkDownloadResponse struct {
	DownloadDuration string `json:"download_duration"`
}

func (c *Client) BenchmarkDownload(ctx context.Context, endpoint string) (*BenchmarkDownloadResponse, error) {
	req := &BenchmarkDownloadRequest{Endpoint: endpoint}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/benchmark/download", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil {
			if errMsg, ok := errResp["error"]; ok {
				return nil, fmt.Errorf("benchmark download failed: %s", errMsg)
			}
		}
		return nil, fmt.Errorf("benchmark download failed with status: %d", resp.StatusCode)
	}

	var result BenchmarkDownloadResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}
