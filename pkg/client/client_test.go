package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/storacha/delegator/internal/models"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		wantErr bool
	}{
		{
			name:    "valid URL",
			baseURL: "http://localhost:8080",
			wantErr: false,
		},
		{
			name:    "URL without scheme",
			baseURL: "localhost:8080",
			wantErr: false,
		},
		{
			name:    "empty URL",
			baseURL: "",
			wantErr: true,
		},
		{
			name:    "invalid URL",
			baseURL: "://invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := New(tt.baseURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && client == nil {
				t.Error("New() returned nil client")
			}
		})
	}
}

func TestClientWithOptions(t *testing.T) {
	customClient := &http.Client{Timeout: 5 * time.Second}
	userAgent := "test-client/1.0"

	client, err := New("http://localhost:8080",
		WithHTTPClient(customClient),
		WithUserAgent(userAgent),
		WithTimeout(10*time.Second),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if client.httpClient != customClient {
		t.Error("WithHTTPClient() did not set custom client")
	}
	if client.userAgent != userAgent {
		t.Error("WithUserAgent() did not set custom user agent")
	}
}

func TestHealthCheck(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{
			name:       "healthy service",
			statusCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name:       "unhealthy service",
			statusCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/health" {
					t.Errorf("Expected path /health, got %s", r.URL.Path)
				}
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			client, err := New(server.URL)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			err = client.HealthCheck(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("HealthCheck() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRegisterDID(t *testing.T) {
	tests := []struct {
		name       string
		did        string
		statusCode int
		response   models.APIResponse
		wantErr    bool
	}{
		{
			name:       "successful registration",
			did:        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			statusCode: http.StatusOK,
			response: models.APIResponse{
				Success: true,
				Message: "DID registered successfully",
				Data: models.DIDVerifyResponse{
					SessionID:     "session123",
					DelegationURL: "http://example.com/delegation",
					Instructions:  "Follow these steps: 1. Download delegation 2. Configure node",
				},
			},
			wantErr: false,
		},
		{
			name:    "empty DID",
			did:     "",
			wantErr: true,
		},
		{
			name:       "API error",
			did:        "did:key:invalid",
			statusCode: http.StatusBadRequest,
			response: models.APIResponse{
				Success: false,
				Error:   "invalid_did",
				Message: "Invalid DID format",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.did == "" {
				// Skip server setup for validation tests
				client, err := New("http://localhost:8080")
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}

				_, err = client.RegisterDID(context.Background(), tt.did)
				if !tt.wantErr {
					t.Errorf("RegisterDID() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/onboard/register-did" {
					t.Errorf("Expected path /api/v1/onboard/register-did, got %s", r.URL.Path)
				}
				if r.Method != http.MethodPost {
					t.Errorf("Expected method POST, got %s", r.Method)
				}

				var req models.DIDRegisterRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Errorf("Failed to decode request: %v", err)
				}
				if req.DID != tt.did {
					t.Errorf("Expected DID %s, got %s", tt.did, req.DID)
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.statusCode)
				json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			client, err := New(server.URL)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			resp, err := client.RegisterDID(context.Background(), tt.did)
			if (err != nil) != tt.wantErr {
				t.Errorf("RegisterDID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && resp == nil {
				t.Error("RegisterDID() returned nil response")
			}
		})
	}
}

func TestRegisterFQDN(t *testing.T) {
	tests := []struct {
		name       string
		sessionID  string
		fqdnURL    string
		statusCode int
		response   models.APIResponse
		wantErr    bool
	}{
		{
			name:       "successful registration",
			sessionID:  "session123",
			fqdnURL:    "https://example.com",
			statusCode: http.StatusOK,
			response: models.APIResponse{
				Success: true,
				Message: "FQDN registered successfully",
				Data: models.FQDNVerifyResponse{
					SessionID:    "session123",
					Status:       "fqdn_verified",
					FQDN:         "example.com",
					Instructions: "Proceed to proof submission",
				},
			},
			wantErr: false,
		},
		{
			name:      "empty session ID",
			sessionID: "",
			fqdnURL:   "https://example.com",
			wantErr:   true,
		},
		{
			name:      "empty FQDN URL",
			sessionID: "session123",
			fqdnURL:   "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.sessionID == "" || tt.fqdnURL == "" {
				// Skip server setup for validation tests
				client, err := New("http://localhost:8080")
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}

				_, err = client.RegisterFQDN(context.Background(), tt.sessionID, tt.fqdnURL)
				if !tt.wantErr {
					t.Errorf("RegisterFQDN() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/onboard/register-fqdn" {
					t.Errorf("Expected path /api/v1/onboard/register-fqdn, got %s", r.URL.Path)
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.statusCode)
				json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			client, err := New(server.URL)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			resp, err := client.RegisterFQDN(context.Background(), tt.sessionID, tt.fqdnURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("RegisterFQDN() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && resp == nil {
				t.Error("RegisterFQDN() returned nil response")
			}
		})
	}
}

func TestDownloadDelegation(t *testing.T) {
	delegationData := []byte("delegation content")

	tests := []struct {
		name       string
		sessionID  string
		statusCode int
		response   []byte
		wantErr    bool
	}{
		{
			name:       "successful download",
			sessionID:  "session123",
			statusCode: http.StatusOK,
			response:   delegationData,
			wantErr:    false,
		},
		{
			name:      "empty session ID",
			sessionID: "",
			wantErr:   true,
		},
		{
			name:       "not found",
			sessionID:  "invalid",
			statusCode: http.StatusNotFound,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.sessionID == "" {
				// Skip server setup for validation tests
				client, err := New("http://localhost:8080")
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}

				_, err = client.DownloadDelegation(context.Background(), tt.sessionID)
				if !tt.wantErr {
					t.Errorf("DownloadDelegation() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectedPath := "/api/v1/onboard/delegation/" + tt.sessionID
				if r.URL.Path != expectedPath {
					t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
				}

				w.WriteHeader(tt.statusCode)
				if tt.statusCode == http.StatusOK {
					w.Write(tt.response)
				} else {
					json.NewEncoder(w).Encode(models.ErrorResponse{
						Error:   "not_found",
						Message: "Session not found",
					})
				}
			}))
			defer server.Close()

			client, err := New(server.URL)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			data, err := client.DownloadDelegation(context.Background(), tt.sessionID)
			if (err != nil) != tt.wantErr {
				t.Errorf("DownloadDelegation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && string(data) != string(tt.response) {
				t.Errorf("DownloadDelegation() data = %s, want %s", string(data), string(tt.response))
			}
		})
	}
}

func TestAPIError(t *testing.T) {
	tests := []struct {
		name     string
		err      *APIError
		expected string
	}{
		{
			name: "error with message",
			err: &APIError{
				StatusCode: 400,
				Message:    "Invalid request",
				ErrorCode:  "invalid_request",
			},
			expected: "delegator API error (400): Invalid request",
		},
		{
			name: "error without message",
			err: &APIError{
				StatusCode: 404,
				ErrorCode:  "not_found",
			},
			expected: "delegator API error (404): not_found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("APIError.Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAPIErrorMethods(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		isNotFound bool
		isBadReq   bool
		isForbid   bool
		isConflict bool
	}{
		{
			name:       "not found",
			statusCode: 404,
			isNotFound: true,
		},
		{
			name:       "bad request",
			statusCode: 400,
			isBadReq:   true,
		},
		{
			name:       "forbidden",
			statusCode: 403,
			isForbid:   true,
		},
		{
			name:       "conflict",
			statusCode: 409,
			isConflict: true,
		},
		{
			name:       "other error",
			statusCode: 500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &APIError{StatusCode: tt.statusCode}

			if got := err.IsNotFound(); got != tt.isNotFound {
				t.Errorf("IsNotFound() = %v, want %v", got, tt.isNotFound)
			}
			if got := err.IsBadRequest(); got != tt.isBadReq {
				t.Errorf("IsBadRequest() = %v, want %v", got, tt.isBadReq)
			}
			if got := err.IsForbidden(); got != tt.isForbid {
				t.Errorf("IsForbidden() = %v, want %v", got, tt.isForbid)
			}
			if got := err.IsConflict(); got != tt.isConflict {
				t.Errorf("IsConflict() = %v, want %v", got, tt.isConflict)
			}
		})
	}
}
