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
	"github.com/storacha/go-libstoracha/capabilities/space/egress"
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
	forgetypes "github.com/storacha/forgectl/pkg/services/types"
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

func generateEgressTrackingProof(t *testing.T, egressTrackingSigner, delegatorSigner principal.Signer) delegation.Delegation {
	dlg, err := delegation.Delegate(
		egressTrackingSigner,
		delegatorSigner.DID(),
		[]ucan.Capability[ucan.NoCaveats]{
			ucan.NewCapability(
				egress.TrackAbility,
				egressTrackingSigner.DID().String(),
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
func setupTestServer(t *testing.T, mockStore *mockStore) (*fxtest.App, string, principal.Signer, principal.Signer, principal.Signer, principal.Signer, *mockContractOperator) {
	// Generate test signers
	delegatorSigner := generateTestSigner(t)
	indexingSigner := generateTestSigner(t)
	egressTrackingSigner := generateTestSigner(t)
	uploadSigner := generateTestSigner(t)

	// Create mock contract operator
	mockContractOp := newMockContractOperator()

	// Generate indexing proof
	indexingProof := generateIndexingProof(t, indexingSigner, delegatorSigner)

	// Generate egress tracking proof
	egressTrackingProof := generateEgressTrackingProof(t, egressTrackingSigner, delegatorSigner)

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
			IndexingServiceWebDID:    indexingSigner.DID().String(),
			EgressTrackingServiceDID: egressTrackingSigner.DID().String(),
			UploadServiceDID:         uploadSigner.DID().String(),
		},
	}

	// Create the test app with fx
	app := fxtest.New(t,
		fx.Provide(
			func() *config.Config { return testConfig },
			func() store.Store { return mockStore },
			func() principal.Signer { return delegatorSigner },
			fx.Annotate(
				func() (did.DID, error) {
					return did.Parse(indexingSigner.DID().String())
				},
				fx.ResultTags(`name:"indexing_service_web_did"`),
			),
			fx.Annotate(
				func() (did.DID, error) {
					return did.Parse(egressTrackingSigner.DID().String())
				},
				fx.ResultTags(`name:"egress_tracking_service_did"`),
			),
			fx.Annotate(
				func() did.DID { return uploadSigner.DID() },
				fx.ResultTags(`name:"upload_service_did"`),
			),
			fx.Annotate(
				func() delegation.Delegation { return indexingProof },
				fx.ResultTags(`name:"indexing_service_proof"`),
			),
			fx.Annotate(
				func() delegation.Delegation { return egressTrackingProof },
				fx.ResultTags(`name:"egress_tracking_service_proof"`),
			),
			func() registrar.ContractOperator { return mockContractOp },
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

	return app, serverURL, delegatorSigner, indexingSigner, egressTrackingSigner, uploadSigner, mockContractOp
}

func TestSystemHealthCheck(t *testing.T) {
	mockStore := newMockStore()
	app, serverURL, _, _, _, _, _ := setupTestServer(t, mockStore)
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

func TestSystemDIDDocument(t *testing.T) {
	mockStore := newMockStore()
	app, serverURL, delegatorSigner, _, _, _, _ := setupTestServer(t, mockStore)
	defer app.RequireStop()

	// Create client
	c, err := client.New(serverURL)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Test DID document endpoint
	ctx := context.Background()
	doc, err := c.DIDDocument(ctx)
	if err != nil {
		t.Fatalf("get did document failed: %v", err)
	}

	if doc.ID != delegatorSigner.DID().String() {
		t.Fatalf("unexpected id: got %s, want %s", doc.ID, delegatorSigner.DID().String())
	}
}

func TestSystemRegistrationFlow(t *testing.T) {
	mockStore := newMockStore()
	app, serverURL, _, _, _, uploadSigner, _ := setupTestServer(t, mockStore)
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
			Operator:      storageNode.did.String(),
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
			Operator:      storageNode.did.String(),
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
			Operator:      unauthorizedSigner.DID().String(),
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
	app, serverURL, _, _, _, uploadSigner, _ := setupTestServer(t, mockStore)
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
		Operator:      storageNode.did.String(),
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

func TestSystemRequestProofs(t *testing.T) {
	mockStore := newMockStore()
	app, serverURL, delegatorSigner, indexingSigner, egressTrackingSigner, uploadSigner, _ := setupTestServer(t, mockStore)
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
		Operator:      storageNode.did.String(),
		OwnerAddress:  common.HexToAddress("0x1234567890123456789012345678901234567890").String(),
		ProofSetID:    1,
		OperatorEmail: "test@example.com",
		PublicURL:     storageNode.url(),
		Proof:         proof,
	})
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	t.Run("request proofs for registered DID", func(t *testing.T) {
		resp, err := c.RequestProofs(ctx, storageNode.did.String())
		if err != nil {
			t.Fatalf("request proof failed: %v", err)
		}

		// Verify indexer proof
		if resp.Proofs.Indexer == "" {
			t.Fatal("expected indexer proof to be returned")
		}

		// Verify the proof is valid
		indxrDlg, err := delegation.Parse(resp.Proofs.Indexer)
		if err != nil {
			t.Fatalf("failed to parse returned indexer proof: %v", err)
		}

		// Verify issuer is the delegator
		if indxrDlg.Issuer().DID().String() != delegatorSigner.DID().String() {
			t.Fatalf("unexpected indexer proof issuer: got %s, want %s", indxrDlg.Issuer().DID().String(), delegatorSigner.DID().String())
		}

		// Verify audience is the storage node
		if indxrDlg.Audience().DID().String() != storageNode.did.String() {
			t.Fatalf("unexpected indexer proof audience: got %s, want %s", indxrDlg.Audience().DID().String(), storageNode.did.String())
		}

		// Verify capability
		caps := indxrDlg.Capabilities()
		if len(caps) != 1 {
			t.Fatalf("unexpected number of capabilities in indexer proof: got %d, want 1", len(caps))
		}
		if caps[0].Can() != claim.CacheAbility {
			t.Fatalf("unexpected capability in indexer proof: got %s, want %s", caps[0].Can(), claim.CacheAbility)
		}
		if caps[0].With() != indexingSigner.DID().String() {
			t.Fatalf("unexpected capability resource in indexer proof: got %s, want %s", caps[0].With(), indexingSigner.DID().String())
		}

		// Verify egress tracker proof
		if resp.Proofs.EgressTracker == "" {
			t.Fatal("expected egress tracker proof to be returned")
		}

		// Verify the proof is valid
		etrackerDlg, err := delegation.Parse(resp.Proofs.EgressTracker)
		if err != nil {
			t.Fatalf("failed to parse returned egress tracker proof: %v", err)
		}

		// Verify issuer is the delegator
		if etrackerDlg.Issuer().DID().String() != delegatorSigner.DID().String() {
			t.Fatalf("unexpected egress tracker proof issuer: got %s, want %s", etrackerDlg.Issuer().DID().String(), delegatorSigner.DID().String())
		}

		// Verify audience is the storage node
		if etrackerDlg.Audience().DID().String() != storageNode.did.String() {
			t.Fatalf("unexpected egress tracker proof audience: got %s, want %s", etrackerDlg.Audience().DID().String(), storageNode.did.String())
		}

		// Verify capability
		caps = etrackerDlg.Capabilities()
		if len(caps) != 1 {
			t.Fatalf("unexpected number of capabilities in egress tracker proof: got %d, want 1", len(caps))
		}
		if caps[0].Can() != egress.TrackAbility {
			t.Fatalf("unexpected capability in egress tracker proof: got %s, want %s", caps[0].Can(), egress.TrackAbility)
		}
		if caps[0].With() != egressTrackingSigner.DID().String() {
			t.Fatalf("unexpected capability resource in indexer proof: got %s, want %s", caps[0].With(), egressTrackingSigner.DID().String())
		}
	})

	t.Run("request proof for unregistered DID", func(t *testing.T) {
		unregisteredSigner := generateTestSigner(t)
		mockStore.allowDID(unregisteredSigner.DID()) // Allow but don't register

		_, err := c.RequestProofs(ctx, unregisteredSigner.DID().String())
		if err == nil {
			t.Fatal("expected request proof to fail for unregistered DID")
		}
	})

	t.Run("request proof for unauthorized DID", func(t *testing.T) {
		unauthorizedSigner := generateTestSigner(t)
		// Don't allow this DID

		_, err := c.RequestProofs(ctx, unauthorizedSigner.DID().String())
		if err == nil {
			t.Fatal("expected request proof to fail for unauthorized DID")
		}
	})
}

func TestSystemEndToEndWorkflow(t *testing.T) {
	mockStore := newMockStore()
	app, serverURL, _, _, _, uploadSigner, _ := setupTestServer(t, mockStore)
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
	_, err = c.RequestProofs(ctx, storageNode.did.String())
	if err == nil {
		t.Fatal("expected request proof to fail before registration")
	}

	// Step 3: Register the node
	proof := generateTestProof(t, storageNode.signer, uploadSigner,
		[]string{blob.AcceptAbility, blob.AllocateAbility, replica.AllocateAbility, pdp.InfoAbility},
		storageNode.did)

	err = c.Register(ctx, &client.RegisterRequest{
		Operator:      storageNode.did.String(),
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
	proofResp, err := c.RequestProofs(ctx, storageNode.did.String())
	if err != nil {
		t.Fatalf("request proof failed: %v", err)
	}
	if proofResp.Proofs.Indexer == "" {
		t.Fatal("expected indexer proof to be returned")
	}
	if proofResp.Proofs.EgressTracker == "" {
		t.Fatal("expected egress tracker proof to be returned")
	}

	// Step 6: Verify the proofs can be parsed and are valid
	dlg, err := delegation.Parse(proofResp.Proofs.Indexer)
	if err != nil {
		t.Fatalf("failed to parse indexer proof: %v", err)
	}
	if dlg.Audience().DID().String() != storageNode.did.String() {
		t.Fatalf("indexer proof audience mismatch: got %s, want %s", dlg.Audience().DID().String(), storageNode.did.String())
	}

	dlg, err = delegation.Parse(proofResp.Proofs.EgressTracker)
	if err != nil {
		t.Fatalf("failed to parse egress tracker proof: %v", err)
	}
	if dlg.Audience().DID().String() != storageNode.did.String() {
		t.Fatalf("egress tracker proof audience mismatch: got %s, want %s", dlg.Audience().DID().String(), storageNode.did.String())
	}
}

func TestSystemInvalidRequests(t *testing.T) {
	mockStore := newMockStore()
	app, serverURL, _, _, _, _, _ := setupTestServer(t, mockStore)
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
			name:     "deprecated method registrar/request-proof returns 410",
			method:   "GET",
			endpoint: "/registrar/request-proof",
			body:     `{"did": "did:key:z6MksvRCPWoXvMj8sUzuHiQ4pFkSawkKRz2eh1TALNEG6s3e"}`,
			wantCode: http.StatusGone,
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

// mockContractOperator implements the registrar.ContractOperator interface for testing
type mockContractOperator struct {
	mu                  sync.RWMutex
	registeredProviders map[string]*forgetypes.ProviderInfo
	approvedProviders   map[uint64]bool
	nextProviderID      uint64
}

func newMockContractOperator() *mockContractOperator {
	return &mockContractOperator{
		registeredProviders: make(map[string]*forgetypes.ProviderInfo),
		approvedProviders:   make(map[uint64]bool),
		nextProviderID:      1,
	}
}

func (m *mockContractOperator) IsRegisteredProvider(ctx context.Context, provider common.Address) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.registeredProviders[provider.String()]
	return exists, nil
}

func (m *mockContractOperator) GetProviderByAddress(ctx context.Context, provider common.Address) (*forgetypes.ProviderInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	info, exists := m.registeredProviders[provider.String()]
	if !exists {
		return nil, fmt.Errorf("provider not found")
	}
	return info, nil
}

func (m *mockContractOperator) ApproveProvider(ctx context.Context, id uint64) (*forgetypes.ApprovalResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.approvedProviders[id] = true
	return &forgetypes.ApprovalResult{
		ProviderID:      id,
		TransactionHash: common.HexToHash("0x1234567890abcdef"),
	}, nil
}

func (m *mockContractOperator) registerProvider(address common.Address, isApproved bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.nextProviderID
	m.nextProviderID++
	m.registeredProviders[address.String()] = &forgetypes.ProviderInfo{
		ID:         id,
		IsApproved: isApproved,
	}
}

func TestSystemRequestContractApproval(t *testing.T) {
	mockStore := newMockStore()
	app, serverURL, _, _, _, _, mockContractOp := setupTestServer(t, mockStore)
	defer app.RequireStop()

	// Create client
	c, err := client.New(serverURL)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()

	// Test provider address
	testAddress := common.HexToAddress("0x1234567890123456789012345678901234567890")

	t.Run("successful contract approval", func(t *testing.T) {
		// Create a test signer
		signer := generateTestSigner(t)
		mockStore.allowDID(signer.DID())
		mockContractOp.registerProvider(testAddress, false) // Register but not yet approved

		// Sign the DID with the signer's private key to prove ownership
		signature := signer.Sign(signer.DID().Bytes())

		err = c.RequestApproval(ctx, &client.RequestApprovalRequest{
			Operator:     signer.DID().String(),
			OwnerAddress: testAddress.String(),
			Signature:    signature.Raw(),
		})
		if err != nil {
			t.Fatalf("contract approval failed: %v", err)
		}
	})

	t.Run("DID not in allow list", func(t *testing.T) {
		// Create a test signer but don't add to allow list
		signer := generateTestSigner(t)
		testAddr := common.HexToAddress("0x2234567890123456789012345678901234567890")

		signature := signer.Sign(signer.DID().Bytes())

		err = c.RequestApproval(ctx, &client.RequestApprovalRequest{
			Operator:     signer.DID().String(),
			OwnerAddress: testAddr.String(),
			Signature:    signature.Raw(),
		})
		if err == nil {
			t.Fatal("expected contract approval to fail for DID not in allow list")
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		// Create a test signer and add to allow list
		signer := generateTestSigner(t)
		mockStore.allowDID(signer.DID())
		testAddr := common.HexToAddress("0x3234567890123456789012345678901234567890")
		mockContractOp.registerProvider(testAddr, false)

		// Use an invalid signature
		invalidSignature := make([]byte, 64)

		err = c.RequestApproval(ctx, &client.RequestApprovalRequest{
			Operator:     signer.DID().String(),
			OwnerAddress: testAddr.String(),
			Signature:    invalidSignature,
		})
		if err == nil {
			t.Fatal("expected contract approval to fail with invalid signature")
		}
	})

	t.Run("provider not registered with contract", func(t *testing.T) {
		// Create a test signer and add to allow list but don't register with contract
		signer := generateTestSigner(t)
		mockStore.allowDID(signer.DID())
		testAddr := common.HexToAddress("0x4234567890123456789012345678901234567890")
		// Do NOT register with contract

		signature := signer.Sign(signer.DID().Bytes())

		err = c.RequestApproval(ctx, &client.RequestApprovalRequest{
			Operator:     signer.DID().String(),
			OwnerAddress: testAddr.String(),
			Signature:    signature.Raw(),
		})
		if err == nil {
			t.Fatal("expected contract approval to fail for provider not registered with contract")
		}
	})

	t.Run("already approved provider (idempotent)", func(t *testing.T) {
		// Create a test signer
		signer := generateTestSigner(t)
		mockStore.allowDID(signer.DID())
		testAddr := common.HexToAddress("0x5234567890123456789012345678901234567890")
		mockContractOp.registerProvider(testAddr, true) // Already approved

		signature := signer.Sign(signer.DID().Bytes())

		// Should succeed even if already approved (idempotent behavior)
		err = c.RequestApproval(ctx, &client.RequestApprovalRequest{
			Operator:     signer.DID().String(),
			OwnerAddress: testAddr.String(),
			Signature:    signature.Raw(),
		})
		if err != nil {
			t.Fatalf("contract approval failed for already approved provider: %v", err)
		}
	})
}
