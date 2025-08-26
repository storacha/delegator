package test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/labstack/echo/v4"
	"github.com/storacha/go-libstoracha/capabilities/blob"
	"github.com/storacha/go-libstoracha/capabilities/blob/replica"
	"github.com/storacha/go-libstoracha/capabilities/claim"
	"github.com/storacha/go-libstoracha/capabilities/pdp"
	"github.com/storacha/go-ucanto/core/delegation"
	"github.com/storacha/go-ucanto/did"
	"github.com/storacha/go-ucanto/principal"
	ed25519signer "github.com/storacha/go-ucanto/principal/ed25519/signer"
	"github.com/storacha/go-ucanto/ucan"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"

	"github.com/storacha/delegator/client"
	"github.com/storacha/delegator/internal/config"
	"github.com/storacha/delegator/internal/handlers"
	"github.com/storacha/delegator/internal/server"
	"github.com/storacha/delegator/internal/services/benchmark"
	"github.com/storacha/delegator/internal/services/registrar"
	"github.com/storacha/delegator/internal/store"
)

// mockStore implements the store.Store interface for testing
type mockStore struct {
	mu             sync.RWMutex
	allowedDIDs    map[string]bool
	registeredDIDs map[string]store.StorageProviderInfo
}

func (m *mockStore) AddAllowedDID(ctx context.Context, did did.DID) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.allowedDIDs[did.String()] = true
	return nil
}

func (m *mockStore) RemoveAllowedDID(ctx context.Context, did did.DID) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	delete(m.allowedDIDs, did.String())
	return nil
}

func newMockStore() *mockStore {
	return &mockStore{
		allowedDIDs:    make(map[string]bool),
		registeredDIDs: make(map[string]store.StorageProviderInfo),
	}
}

func (m *mockStore) IsAllowedDID(ctx context.Context, did did.DID) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.allowedDIDs[did.String()], nil
}

func (m *mockStore) IsRegisteredDID(ctx context.Context, did did.DID) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.registeredDIDs[did.String()]
	return exists, nil
}

func (m *mockStore) RegisterProvider(ctx context.Context, provider store.StorageProviderInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registeredDIDs[provider.Provider] = provider
	return nil
}

func (m *mockStore) allowDID(did did.DID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allowedDIDs[did.String()] = true
}

func (m *mockStore) getProvider(did did.DID) (store.StorageProviderInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	provider, exists := m.registeredDIDs[did.String()]
	return provider, exists
}

// Helper functions for test data generation
func generateTestSigner(t *testing.T) principal.Signer {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	signer, err := ed25519signer.FromRaw(priv)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	return signer
}

func generateTestProof(t *testing.T, issuer, audience principal.Signer, abilities []string, resource did.DID) string {
	caps := make([]ucan.Capability[ucan.NoCaveats], 0, len(abilities))
	for _, ability := range abilities {
		caps = append(caps, ucan.NewCapability(
			ability,
			resource.String(),
			ucan.NoCaveats{},
		))
	}

	dlg, err := delegation.Delegate(
		issuer,
		audience.DID(),
		caps,
		delegation.WithNoExpiration(),
	)
	if err != nil {
		t.Fatalf("failed to create delegation: %v", err)
	}

	proof, err := delegation.Format(dlg)
	if err != nil {
		t.Fatalf("failed to format delegation: %v", err)
	}

	return proof
}

func generateIndexingProof(t *testing.T, indexingSigner, delegatorSigner principal.Signer) delegation.Delegation {
	dlg, err := delegation.Delegate(
		indexingSigner,
		delegatorSigner.DID(),
		[]ucan.Capability[ucan.NoCaveats]{
			ucan.NewCapability(
				claim.CacheAbility,
				indexingSigner.DID().String(),
				ucan.NoCaveats{},
			),
		},
		delegation.WithNoExpiration(),
	)
	if err != nil {
		t.Fatalf("failed to create indexing proof: %v", err)
	}
	return dlg
}

// mockStorageNode simulates a storage node server
type mockStorageNode struct {
	server  *httptest.Server
	did     did.DID
	signer  principal.Signer
	handler *echo.Echo
}

func newMockStorageNode(t *testing.T) *mockStorageNode {
	signer := generateTestSigner(t)
	e := echo.New()
	e.HideBanner = true

	node := &mockStorageNode{
		did:     signer.DID(),
		signer:  signer,
		handler: e,
	}

	// Mock storage node endpoints
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, fmt.Sprintf("🔥 storage v0.0.3\n- https://github.com/storacha/storage\n- %s", node.did.String()))
	})

	// Mock blob allocate endpoint
	e.POST("/allocate", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"url": node.server.URL + "/upload",
			"headers": map[string]string{
				"Authorization": "Bearer test-token",
			},
		})
	})

	// Mock blob upload endpoint
	e.PUT("/upload", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	// Mock blob accept endpoint
	e.POST("/accept", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"locationCommitment": map[string]interface{}{
				"location": []string{node.server.URL + "/download/test"},
			},
			"pdpAccept": map[string]interface{}{
				"piece": map[string]interface{}{
					"link": "baga6ea4seaqtest",
				},
			},
		})
	})

	// Mock download endpoint
	e.GET("/download/:id", func(c echo.Context) error {
		// Return some test data
		data := make([]byte, 1024)
		return c.Blob(http.StatusOK, "application/octet-stream", data)
	})

	node.server = httptest.NewServer(node.handler)
	return node
}

func (n *mockStorageNode) close() {
	n.server.Close()
}

func (n *mockStorageNode) url() string {
	return n.server.URL
}

// Test server setup
func setupTestServer(t *testing.T, mockStore *mockStore) (*fxtest.App, string, principal.Signer, principal.Signer, principal.Signer) {
	// Generate test signers
	delegatorSigner := generateTestSigner(t)
	indexingSigner := generateTestSigner(t)
	uploadSigner := generateTestSigner(t)

	// Generate indexing proof
	indexingProof := generateIndexingProof(t, indexingSigner, delegatorSigner)

	// Get a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	// Create test configuration
	testConfig := &config.Config{
		Server: config.ServerConfig{
			Host: "127.0.0.1",
			Port: port,
		},
		Delegator: config.DelegatorServiceConfig{
			IndexingServiceWebDID: indexingSigner.DID().String(),
			UploadServiceDID:      uploadSigner.DID().String(),
		},
	}

	// Create the test app with fx
	app := fxtest.New(t,
		fx.Provide(
			func() *config.Config { return testConfig },
			func() store.Store { return mockStore },
			func() principal.Signer { return delegatorSigner },
			func() (did.DID, error) {
				return did.Parse(indexingSigner.DID().String())
			},
			fx.Annotate(
				func(d did.DID) did.DID { return d },
				fx.ResultTags(`name:"indexing_service_web_did"`),
			),
			fx.Annotate(
				func() did.DID { return uploadSigner.DID() },
				fx.ResultTags(`name:"upload_service_did"`),
			),
			fx.Annotate(
				func() delegation.Delegation { return indexingProof },
				fx.ResultTags(`name:"indexing_service_proof"`),
			),
			registrar.New,
			benchmark.New,
			handlers.NewHandlers,
			server.NewServer,
		),
		fx.Invoke(server.Start),
	)

	app.RequireStart()

	// Wait for server to be ready
	serverURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	for i := 0; i < 50; i++ {
		resp, err := http.Get(serverURL + "/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	return app, serverURL, delegatorSigner, indexingSigner, uploadSigner
}

func TestSystemHealthCheck(t *testing.T) {
	mockStore := newMockStore()
	app, serverURL, _, _, _ := setupTestServer(t, mockStore)
	defer app.RequireStop()

	// Create client
	c, err := client.New(serverURL)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Test health check
	ctx := context.Background()
	err = c.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
}

func TestSystemRegistrationFlow(t *testing.T) {
	mockStore := newMockStore()
	app, serverURL, _, _, uploadSigner := setupTestServer(t, mockStore)
	defer app.RequireStop()

	// Create client
	c, err := client.New(serverURL)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Create a mock storage node
	storageNode := newMockStorageNode(t)
	defer storageNode.close()

	// Allow the storage node DID
	mockStore.allowDID(storageNode.did)

	// Generate proof for registration
	proof := generateTestProof(t, storageNode.signer, uploadSigner,
		[]string{blob.AcceptAbility, blob.AllocateAbility, replica.AllocateAbility, pdp.InfoAbility},
		storageNode.did)

	ctx := context.Background()

	// Test registration
	t.Run("successful registration", func(t *testing.T) {
		err = c.Register(ctx, &client.RegisterRequest{
			DID:           storageNode.did.String(),
			OwnerAddress:  common.HexToAddress("0x1234567890123456789012345678901234567890").String(),
			ProofSetID:    1,
			OperatorEmail: "test@example.com",
			PublicURL:     storageNode.url(),
			Proof:         proof,
		})
		if err != nil {
			t.Fatalf("registration failed: %v", err)
		}

		// Verify registration in store
		provider, exists := mockStore.getProvider(storageNode.did)
		if !exists {
			t.Fatal("provider not found in store after registration")
		}
		if provider.Provider != storageNode.did.String() {
			t.Fatalf("unexpected provider DID: got %s, want %s", provider.Provider, storageNode.did.String())
		}
	})

	t.Run("duplicate registration should fail", func(t *testing.T) {
		err = c.Register(ctx, &client.RegisterRequest{
			DID:           storageNode.did.String(),
			OwnerAddress:  common.HexToAddress("0x1234567890123456789012345678901234567890").String(),
			ProofSetID:    1,
			OperatorEmail: "test@example.com",
			PublicURL:     storageNode.url(),
			Proof:         proof,
		})
		if err == nil {
			t.Fatal("expected duplicate registration to fail")
		}
	})

	t.Run("unauthorized DID registration should fail", func(t *testing.T) {
		unauthorizedSigner := generateTestSigner(t)
		unauthorizedNode := newMockStorageNode(t)
		defer unauthorizedNode.close()

		proof := generateTestProof(t, unauthorizedSigner, uploadSigner,
			[]string{blob.AcceptAbility, blob.AllocateAbility, replica.AllocateAbility, pdp.InfoAbility},
			unauthorizedSigner.DID())

		err = c.Register(ctx, &client.RegisterRequest{
			DID:           unauthorizedSigner.DID().String(),
			OwnerAddress:  common.HexToAddress("0x1234567890123456789012345678901234567890").String(),
			ProofSetID:    1,
			OperatorEmail: "test@example.com",
			PublicURL:     unauthorizedNode.url(),
			Proof:         proof,
		})
		if err == nil {
			t.Fatal("expected unauthorized registration to fail")
		}
	})
}

func TestSystemIsRegistered(t *testing.T) {
	mockStore := newMockStore()
	app, serverURL, _, _, uploadSigner := setupTestServer(t, mockStore)
	defer app.RequireStop()

	// Create client
	c, err := client.New(serverURL)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()

	// Create and register a storage node
	storageNode := newMockStorageNode(t)
	defer storageNode.close()
	mockStore.allowDID(storageNode.did)

	proof := generateTestProof(t, storageNode.signer, uploadSigner,
		[]string{blob.AcceptAbility, blob.AllocateAbility, replica.AllocateAbility, pdp.InfoAbility},
		storageNode.did)

	// Register the node
	err = c.Register(ctx, &client.RegisterRequest{
		DID:           storageNode.did.String(),
		OwnerAddress:  common.HexToAddress("0x1234567890123456789012345678901234567890").String(),
		ProofSetID:    1,
		OperatorEmail: "test@example.com",
		PublicURL:     storageNode.url(),
		Proof:         proof,
	})
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	t.Run("check registered DID", func(t *testing.T) {
		registered, err := c.IsRegistered(ctx, &client.IsRegisteredRequest{
			DID: storageNode.did.String(),
		})
		if err != nil {
			t.Fatalf("is registered check failed: %v", err)
		}
		if !registered {
			t.Fatal("expected DID to be registered")
		}
	})

	t.Run("check unregistered DID", func(t *testing.T) {
		unregisteredSigner := generateTestSigner(t)
		registered, err := c.IsRegistered(ctx, &client.IsRegisteredRequest{
			DID: unregisteredSigner.DID().String(),
		})
		if err != nil {
			t.Fatalf("is registered check failed: %v", err)
		}
		if registered {
			t.Fatal("expected DID to not be registered")
		}
	})
}

func TestSystemRequestProof(t *testing.T) {
	mockStore := newMockStore()
	app, serverURL, delegatorSigner, indexingSigner, uploadSigner := setupTestServer(t, mockStore)
	defer app.RequireStop()

	// Create client
	c, err := client.New(serverURL)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()

	// Create and register a storage node
	storageNode := newMockStorageNode(t)
	defer storageNode.close()
	mockStore.allowDID(storageNode.did)

	proof := generateTestProof(t, storageNode.signer, uploadSigner,
		[]string{blob.AcceptAbility, blob.AllocateAbility, replica.AllocateAbility, pdp.InfoAbility},
		storageNode.did)

	// Register the node
	err = c.Register(ctx, &client.RegisterRequest{
		DID:           storageNode.did.String(),
		OwnerAddress:  common.HexToAddress("0x1234567890123456789012345678901234567890").String(),
		ProofSetID:    1,
		OperatorEmail: "test@example.com",
		PublicURL:     storageNode.url(),
		Proof:         proof,
	})
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	t.Run("request proof for registered DID", func(t *testing.T) {
		resp, err := c.RequestProof(ctx, storageNode.did.String())
		if err != nil {
			t.Fatalf("request proof failed: %v", err)
		}
		if resp.Proof == "" {
			t.Fatal("expected proof to be returned")
		}

		// Verify the proof is valid
		dlg, err := delegation.Parse(resp.Proof)
		if err != nil {
			t.Fatalf("failed to parse returned proof: %v", err)
		}

		// Verify issuer is the delegator
		if dlg.Issuer().DID().String() != delegatorSigner.DID().String() {
			t.Fatalf("unexpected proof issuer: got %s, want %s", dlg.Issuer().DID().String(), delegatorSigner.DID().String())
		}

		// Verify audience is the storage node
		if dlg.Audience().DID().String() != storageNode.did.String() {
			t.Fatalf("unexpected proof audience: got %s, want %s", dlg.Audience().DID().String(), storageNode.did.String())
		}

		// Verify capability
		caps := dlg.Capabilities()
		if len(caps) != 1 {
			t.Fatalf("unexpected number of capabilities: got %d, want 1", len(caps))
		}
		if caps[0].Can() != claim.CacheAbility {
			t.Fatalf("unexpected capability: got %s, want %s", caps[0].Can(), claim.CacheAbility)
		}
		if caps[0].With() != indexingSigner.DID().String() {
			t.Fatalf("unexpected capability resource: got %s, want %s", caps[0].With(), indexingSigner.DID().String())
		}
	})

	t.Run("request proof for unregistered DID", func(t *testing.T) {
		unregisteredSigner := generateTestSigner(t)
		mockStore.allowDID(unregisteredSigner.DID()) // Allow but don't register

		_, err := c.RequestProof(ctx, unregisteredSigner.DID().String())
		if err == nil {
			t.Fatal("expected request proof to fail for unregistered DID")
		}
	})

	t.Run("request proof for unauthorized DID", func(t *testing.T) {
		unauthorizedSigner := generateTestSigner(t)
		// Don't allow this DID

		_, err := c.RequestProof(ctx, unauthorizedSigner.DID().String())
		if err == nil {
			t.Fatal("expected request proof to fail for unauthorized DID")
		}
	})
}

func TestSystemEndToEndWorkflow(t *testing.T) {
	mockStore := newMockStore()
	app, serverURL, _, _, uploadSigner := setupTestServer(t, mockStore)
	defer app.RequireStop()

	// Create client
	c, err := client.New(serverURL)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()

	// Create a mock storage node
	storageNode := newMockStorageNode(t)
	defer storageNode.close()

	// Allow the storage node DID
	mockStore.allowDID(storageNode.did)

	// Step 1: Check that node is not registered
	registered, err := c.IsRegistered(ctx, &client.IsRegisteredRequest{
		DID: storageNode.did.String(),
	})
	if err != nil {
		t.Fatalf("is registered check failed: %v", err)
	}
	if registered {
		t.Fatal("expected DID to not be registered initially")
	}

	// Step 2: Try to request proof before registration (should fail)
	_, err = c.RequestProof(ctx, storageNode.did.String())
	if err == nil {
		t.Fatal("expected request proof to fail before registration")
	}

	// Step 3: Register the node
	proof := generateTestProof(t, storageNode.signer, uploadSigner,
		[]string{blob.AcceptAbility, blob.AllocateAbility, replica.AllocateAbility, pdp.InfoAbility},
		storageNode.did)

	err = c.Register(ctx, &client.RegisterRequest{
		DID:           storageNode.did.String(),
		OwnerAddress:  common.HexToAddress("0x1234567890123456789012345678901234567890").String(),
		ProofSetID:    1,
		OperatorEmail: "test@example.com",
		PublicURL:     storageNode.url(),
		Proof:         proof,
	})
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	// Step 4: Verify node is now registered
	registered, err = c.IsRegistered(ctx, &client.IsRegisteredRequest{
		DID: storageNode.did.String(),
	})
	if err != nil {
		t.Fatalf("is registered check failed: %v", err)
	}
	if !registered {
		t.Fatal("expected DID to be registered after registration")
	}

	// Step 5: Request proof after registration (should succeed)
	proofResp, err := c.RequestProof(ctx, storageNode.did.String())
	if err != nil {
		t.Fatalf("request proof failed: %v", err)
	}
	if proofResp.Proof == "" {
		t.Fatal("expected proof to be returned")
	}

	// Step 6: Verify the proof can be parsed and is valid
	dlg, err := delegation.Parse(proofResp.Proof)
	if err != nil {
		t.Fatalf("failed to parse proof: %v", err)
	}
	if dlg.Audience().DID().String() != storageNode.did.String() {
		t.Fatalf("proof audience mismatch: got %s, want %s", dlg.Audience().DID().String(), storageNode.did.String())
	}
}

func TestSystemInvalidRequests(t *testing.T) {
	mockStore := newMockStore()
	app, serverURL, _, _, _ := setupTestServer(t, mockStore)
	defer app.RequireStop()

	ctx := context.Background()

	tests := []struct {
		name     string
		method   string
		endpoint string
		body     string
		wantCode int
	}{
		{
			name:     "malformed JSON in register",
			method:   "PUT",
			endpoint: "/registrar/register-node",
			body:     `{"invalid json`,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "invalid DID in register",
			method:   "PUT",
			endpoint: "/registrar/register-node",
			body:     `{"did": "not-a-did", "owner_address": "0x1234567890123456789012345678901234567890", "proof_set_id": 1, "operator_email": "test@example.com", "public_url": "http://example.com", "proof": "test"}`,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "invalid address in register",
			method:   "PUT",
			endpoint: "/registrar/register-node",
			body:     `{"did": "did:key:z6MksvRCPWoXvMj8sUzuHiQ4pFkSawkKRz2eh1TALNEG6s3e", "owner_address": "not-an-address", "proof_set_id": 1, "operator_email": "test@example.com", "public_url": "http://example.com", "proof": "test"}`,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "malformed JSON in is-registered",
			method:   "GET",
			endpoint: "/registrar/is-registered",
			body:     `{"invalid json`,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "invalid DID in is-registered",
			method:   "GET",
			endpoint: "/registrar/is-registered",
			body:     `{"did": "not-a-did"}`,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "malformed JSON in request-proof",
			method:   "GET",
			endpoint: "/registrar/request-proof",
			body:     `{"invalid json`,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "invalid DID in request-proof",
			method:   "GET",
			endpoint: "/registrar/request-proof",
			body:     `{"did": "not-a-did"}`,
			wantCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(ctx, tt.method, serverURL+tt.endpoint, bytes.NewReader([]byte(tt.body)))
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantCode {
				t.Errorf("unexpected status code: got %d, want %d", resp.StatusCode, tt.wantCode)
			}
		})
	}
}
