package onboarding

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ipfs/go-cid"
	logging "github.com/ipfs/go-log"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	"github.com/storacha/go-libstoracha/capabilities/blob"
	"github.com/storacha/go-libstoracha/capabilities/blob/replica"
	"github.com/storacha/go-libstoracha/capabilities/claim"
	"github.com/storacha/go-libstoracha/capabilities/pdp"
	"github.com/storacha/go-ucanto/core/delegation"
	"github.com/storacha/go-ucanto/core/ipld/hash/sha256"
	"github.com/storacha/go-ucanto/did"
	"github.com/storacha/go-ucanto/principal"
	"github.com/storacha/go-ucanto/ucan"

	"github.com/storacha/delegator/internal/config"
	"github.com/storacha/delegator/internal/models"
	"github.com/storacha/delegator/internal/storage"
	"github.com/storacha/delegator/pkg/client"
)

var log = logging.Logger("service/onboarding")

// progressReader wraps an io.Reader to track reading progress
type progressReader struct {
	reader      io.Reader
	totalBytes  int64
	bytesRead   int64
	onProgress  func(bytesRead, totalBytes int64)
	lastPercent int
	startTime   time.Time
	lastUpdate  time.Time
}

func newProgressReader(r io.Reader, size int64, onProgress func(bytesRead, totalBytes int64)) *progressReader {
	now := time.Now()
	return &progressReader{
		reader:      r,
		totalBytes:  size,
		bytesRead:   0,
		onProgress:  onProgress,
		lastPercent: -1,
		startTime:   now,
		lastUpdate:  now,
	}
}

func (pr *progressReader) Read(p []byte) (n int, err error) {
	n, err = pr.reader.Read(p)
	pr.bytesRead += int64(n)

	// Calculate percentage
	currentPercent := int(float64(pr.bytesRead) / float64(pr.totalBytes) * 100)

	// Only call progress callback if percentage changed (to avoid too many updates)
	if currentPercent != pr.lastPercent && pr.onProgress != nil {
		pr.onProgress(pr.bytesRead, pr.totalBytes)
		pr.lastPercent = currentPercent
	}

	return n, err
}

// OnboardingService handles WSP onboarding logic
type Service struct {
	sessionStore   storage.SessionStore
	persistedStore storage.PersistentStore

	sessionTimeout     time.Duration
	domainCheckTimeout time.Duration

	delegatorSigner       principal.Signer
	indexingServiceProof  delegation.Proof
	uploadServiceDID      did.DID
	indexingServiceWebDID did.DID
}

type Option func(*Service)

func WithSessionStore(store storage.SessionStore) Option {
	return func(o *Service) {
		o.sessionStore = store
	}
}

func WithPersistedStore(store storage.PersistentStore) Option {
	return func(o *Service) {
		o.persistedStore = store
	}
}

func New(cfg config.OnboardingConfig, opts ...Option) (*Service, error) {
	// parse the upload service DID - used for instructing user to generate a proof to upload service from their
	// storage node.
	uploadServiceDID, err := did.Parse(cfg.UploadServiceDID)
	if err != nil {
		return nil, fmt.Errorf("error parsing configured upload service: %w", err)
	}

	// parse the indexing service DID - used for creating the delegation from deletator to storage node.
	indexingServiceWebDID, err := did.Parse(cfg.IndexingServiceWebDID)
	if err != nil {
		return nil, fmt.Errorf("error parsing configured indexing service: %w", err)
	}

	// extract the indexing service proof - used to creating a delegation to the storage node allowing it to invoke
	// 'claim/cache' on indexer.
	indexerDelegation, err := delegation.Parse(cfg.IndexingServiceProof)
	if err != nil {
		return nil, fmt.Errorf("error parsing indexing service proof: %w", err)
	}
	indexerProof := delegation.FromDelegation(indexerDelegation)

	// read the delegators private key file
	keyF, err := os.Open(cfg.KeyFilePath)
	if err != nil {
		return nil, fmt.Errorf("error opening key file (%s): %w", cfg.KeyFilePath, err)
	}

	delegatorSigner, err := readPrivateKeyFromPEM(keyF)
	if err != nil {
		return nil, fmt.Errorf("error loading delegator signer: %w", err)
	}

	service := &Service{
		sessionStore:          storage.NewMemoryStore(),
		persistedStore:        storage.NewMemoryStore(),
		sessionTimeout:        cfg.SessionTimeout,
		domainCheckTimeout:    cfg.FQDNVerificationTimeout,
		delegatorSigner:       delegatorSigner,
		indexingServiceProof:  indexerProof,
		uploadServiceDID:      uploadServiceDID,
		indexingServiceWebDID: indexingServiceWebDID,
	}

	for _, opt := range opts {
		opt(service)
	}

	return service, nil
}

var (
	ErrPersistedStorageFailure = errors.New("unable to read from persisted storage")
	ErrIsNotAllowed            = errors.New("DID not allowed")
	ErrIsAlreadyRegistered     = errors.New("DID already registered")
	ErrSessionNotFound         = errors.New("session not found")
	ErrInvalidSessionState     = errors.New("invalid session state")
	ErrFQDNVerificationFailed  = errors.New("FQDN verification failed")
	ErrProofVerificationFailed = errors.New("proof verification failed")
)

// RegisterDID performs Step 3.1: DID registration, verification and delegation generation
func (s *Service) RegisterDID(strgDID did.DID, filecoinAddress string, proofSetID uint64, operatorEmail string) (*models.DIDVerifyResponse, error) {
	// Check if DID is in allowlist of the persisted store.
	if allowed, err := s.persistedStore.IsAllowedDID(strgDID.String()); err != nil {
		log.Errorw("failed to check if DID is allowed for registration in persisted store", "did", strgDID.String(), "error", err)
		return nil, ErrPersistedStorageFailure
	} else if !allowed {
		log.Infow("disallowed DID attempted to register and was rejected", "did", strgDID.String())
		return nil, ErrIsNotAllowed
	}

	// Check if DID is already registered
	if registered, err := s.persistedStore.IsRegisteredDID(strgDID.String()); err != nil {
		log.Errorw("failed to check if DID is already resgistered for registration in persisted store", "did", strgDID.String(), "error", err)
		return nil, ErrPersistedStorageFailure
	} else if registered {
		log.Infow("registered DID attempted to register again and was rejected", "did", strgDID.String())
		return nil, ErrIsAlreadyRegistered
	}

	// Check for existing active session
	if existingSession, err := s.sessionStore.GetSessionByDID(strgDID.String()); err == nil {
		// Return existing session if still valid
		if time.Now().Before(existingSession.ExpiresAt) {
			return &models.DIDVerifyResponse{
				SessionID:       existingSession.SessionID,
				DelegationURL:   fmt.Sprintf("/api/v1/onboard/delegation/%s", existingSession.SessionID),
				FilecoinAddress: existingSession.FilecoinAddress,
				ProofSetID:      existingSession.ProofSetID,
				OperatorEmail:   existingSession.OperatorEmail,
			}, nil
		}
	}

	// Generate new session
	sessionID := uuid.New().String()
	now := time.Now()

	// Generate delegation data
	delegationData, err := s.generateDelegation(strgDID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate delegation: %w", err)
	}

	session := &models.OnboardingSession{
		SessionID:       sessionID,
		DID:             strgDID.String(),
		Status:          models.StatusDIDVerified,
		DelegationData:  delegationData,
		FilecoinAddress: filecoinAddress,
		ProofSetID:      proofSetID,
		OperatorEmail:   operatorEmail,
		CreatedAt:       now,
		UpdatedAt:       now,
		ExpiresAt:       now.Add(s.sessionTimeout),
	}

	if err := s.sessionStore.CreateSession(session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &models.DIDVerifyResponse{
		SessionID:       sessionID,
		DelegationURL:   fmt.Sprintf("/api/v1/onboard/delegation/%s", sessionID),
		FilecoinAddress: filecoinAddress,
		ProofSetID:      proofSetID,
		OperatorEmail:   operatorEmail,
	}, nil
}

// GetSessionStatus returns the status of an onboarding session
func (s *Service) GetSessionStatus(sessionID string) (*models.OnboardingStatusResponse, error) {
	session, err := s.sessionStore.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	nextStep := s.getNextStep(session.Status)

	return &models.OnboardingStatusResponse{
		SessionID:       session.SessionID,
		DID:             session.DID,
		Status:          session.Status,
		FilecoinAddress: session.FilecoinAddress,
		ProofSetID:      session.ProofSetID,
		OperatorEmail:   session.OperatorEmail,
		CreatedAt:       session.CreatedAt.Format(time.RFC3339),
		ExpiresAt:       session.ExpiresAt.Format(time.RFC3339),
		NextStep:        nextStep,
	}, nil
}

// GetDelegation returns the delegation data for a session
func (s *Service) GetDelegation(sessionID string) (string, error) {
	session, err := s.sessionStore.GetSession(sessionID)
	if err != nil {
		return "", err
	}

	if session.DelegationData == "" {
		return "", fmt.Errorf("no delegation data available for session: %s", sessionID)
	}

	return session.DelegationData, nil
}

// RegisterFQDN performs Step 3.3: FQDN verification and readiness check
func (s *Service) RegisterFQDN(sessionID string, fqdnURL url.URL) (*models.FQDNVerifyResponse, error) {
	// Debug log
	log.Debugw("RegisterFQDN called", "session_id", sessionID, "url", fqdnURL.String())

	// Get the session
	session, err := s.sessionStore.GetSession(strings.TrimSpace(sessionID))
	if err != nil {
		return nil, ErrSessionNotFound
	}

	log.Debugw("Found session for FQDN registration",
		"session_id", session.SessionID,
		"did", session.DID,
		"status", session.Status,
		"expires_at", session.ExpiresAt)

	// Check if session has expired
	if time.Now().After(session.ExpiresAt) {
		log.Debugw("Session expired",
			"session_id", session.SessionID,
			"expired_at", session.ExpiresAt.Format(time.RFC3339))
		return nil, fmt.Errorf("%w: session expired", ErrInvalidSessionState)
	}

	// Check if session is in the correct state (should be DID verified)
	if session.Status != models.StatusDIDVerified {
		log.Debugw("Wrong session state for FQDN registration",
			"session_id", session.SessionID,
			"expected_status", models.StatusDIDVerified,
			"actual_status", session.Status)
		return nil, fmt.Errorf("%w: expected status '%s', got '%s'",
			ErrInvalidSessionState, models.StatusDIDVerified, session.Status)
	}

	// Verify the FQDN by making a request and checking the DID
	if err := s.verifyFQDNReturnsCorrectDID(fqdnURL, session.DID); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFQDNVerificationFailed, err)
	}

	// Update session with FQDN and new status
	session.FQDN = fqdnURL.String()
	session.Status = models.StatusFQDNVerified
	session.UpdatedAt = time.Now()

	if err := s.sessionStore.UpdateSession(session); err != nil {
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	return &models.FQDNVerifyResponse{
		SessionID: sessionID,
		Status:    models.StatusFQDNVerified,
		FQDN:      fqdnURL.String(),
	}, nil
}

// RegisterProof performs Step 3.4: Proof verification and provider registration
func (s *Service) RegisterProof(sessionID string, proof string) (*models.ProofVerifyResponse, error) {
	// Debug log
	log.Debugw("RegisterProof called", "session_id", sessionID)

	// Get the session
	session, err := s.sessionStore.GetSession(sessionID)
	if err != nil {
		log.Debugw("Session not found for RegisterProof", "session_id", sessionID, "error", err)

		// Try one more time with a trimmed session ID (in case there are whitespace issues)
		trimmedID := strings.TrimSpace(sessionID)
		if trimmedID != sessionID {
			log.Debugw("Trying with trimmed session ID", "trimmed_id", trimmedID)
			session, err = s.sessionStore.GetSession(trimmedID)
			if err == nil {
				sessionID = trimmedID
				log.Debugw("Found session with trimmed ID", "session_id", sessionID)
			}
		}

		if err != nil {
			return nil, ErrSessionNotFound
		}
	}

	log.Debugw("Found session for RegisterProof",
		"session_id", session.SessionID,
		"did", session.DID,
		"status", session.Status,
		"expires_at", session.ExpiresAt)

	// Check if session has expired
	if time.Now().After(session.ExpiresAt) {
		log.Debugw("Session expired for RegisterProof",
			"session_id", session.SessionID,
			"expired_at", session.ExpiresAt.Format(time.RFC3339))
		return nil, fmt.Errorf("%w: session expired", ErrInvalidSessionState)
	}

	// Check if session is in the correct state (should be FQDN verified)
	if session.Status != models.StatusFQDNVerified {
		log.Debugw("Wrong session state for RegisterProof",
			"session_id", session.SessionID,
			"expected_status", models.StatusFQDNVerified,
			"actual_status", session.Status)
		return nil, fmt.Errorf("%w: expected status '%s', got '%s'",
			ErrInvalidSessionState, models.StatusFQDNVerified, session.Status)
	}

	// Validate the proof
	if err := s.validateProof(proof, session.DID); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrProofVerificationFailed, err)
	}

	// Update session with proof and new status
	session.Proof = proof
	session.Status = models.StatusProofVerified
	session.UpdatedAt = time.Now()

	if err := s.sessionStore.UpdateSession(session); err != nil {
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	// Store provider in registry (mimicking DynamoDB)
	if err := s.storeProvider(session); err != nil {
		return nil, fmt.Errorf("failed to store provider: %w", err)
	}

	return &models.ProofVerifyResponse{
		SessionID: sessionID,
		Status:    models.StatusProofVerified,
	}, nil
}

// verifyFQDNReturnsCorrectDID makes an HTTP request to the FQDN and verifies it returns the expected DID
func (s *Service) verifyFQDNReturnsCorrectDID(fqdnURL url.URL, expectedDID string) error {
	// Create HTTP client with reasonable timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Make request to the exact URL provided (TODO eventually add a /did endpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fqdnURL.String(), nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("making request to %s: %w", fqdnURL.String(), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d from %s", resp.StatusCode, fqdnURL.String())
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	// Parse the response to extract DID
	responseText := strings.TrimSpace(string(body))

	// Try to parse as JSON first (in case of structured response)
	var didResponse struct {
		DID string `json:"did"`
	}

	if err := json.Unmarshal(body, &didResponse); err == nil && didResponse.DID != "" {
		// Successfully parsed as JSON
		if didResponse.DID != expectedDID {
			return fmt.Errorf("DID mismatch: expected %s, got %s", expectedDID, didResponse.DID)
		}
		return nil
	}

	// TODO a dedicated DID endpoint on the storage node would be helpful here.
	// Parse plain text response to extract DID
	// Expected format: "🔥 storage v0.0.3-d6f3761-dirty\n- https://github.com/storacha/storage\n- did:key:z6MksvRCPWoXvMj8sUzuHiQ4pFkSawkKRz2eh1TALNEG6s3e"
	lines := strings.Split(responseText, "\n")
	var foundDID string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Look for lines that start with "- did:" or just "did:"
		if strings.HasPrefix(line, "- did:") {
			foundDID = strings.TrimPrefix(line, "- ")
			break
		} else if strings.HasPrefix(line, "did:") {
			foundDID = line
			break
		}
	}

	if foundDID == "" {
		return fmt.Errorf("no DID found in response from %s", fqdnURL.String())
	}

	if foundDID != expectedDID {
		return fmt.Errorf("DID mismatch: expected %s, got %s", expectedDID, foundDID)
	}

	return nil
}

// generateDelegation generates a delegation for the provider (stubbed)
func (s *Service) generateDelegation(strgDID did.DID) (string, error) {
	// the delegator creates a delegation for the storage node to invoke claim/cache w/ proof from indexer.
	indxToStrgDelegation, err := delegation.Delegate(
		s.delegatorSigner,
		strgDID,
		[]ucan.Capability[ucan.NoCaveats]{
			ucan.NewCapability(
				claim.CacheAbility,
				s.indexingServiceWebDID.String(),
				ucan.NoCaveats{},
			),
		},
		delegation.WithNoExpiration(),
		delegation.WithProof(s.indexingServiceProof),
	)
	if err != nil {
		return "", fmt.Errorf("failed to generate delegation from indexing service to storage node: %w", err)
	}

	return delegation.Format(indxToStrgDelegation)
}

// validateProof validates the proof delegation
func (s *Service) validateProof(proof string, providerDID string) error {
	if strings.TrimSpace(proof) == "" {
		return fmt.Errorf("proof cannot be empty")
	}

	strgDelegation, err := delegation.Parse(proof)
	if err != nil {
		return err
	}

	expiration := strgDelegation.Expiration()

	now := time.Now().Unix()
	if expiration != nil {
		if *expiration != 0 && *expiration <= int(now) {
			return fmt.Errorf("delegation expired. expiration: %d, now: %d", expiration, now)
		}
	}
	if strgDelegation.Issuer().DID().String() != providerDID {
		return fmt.Errorf("delegation issuer (%s) does not match provider DID (%s)", strgDelegation.Issuer().DID().String(), providerDID)
	}
	if strgDelegation.Audience().DID().String() != s.uploadServiceDID.DID().String() {
		return fmt.Errorf("delegation audience (%s) does not match upload service DID (%s)", strgDelegation.Audience().DID().String(), s.uploadServiceDID.DID())
	}
	var expectedCapabilities = map[string]struct{}{
		blob.AcceptAbility:      {},
		blob.AllocateAbility:    {},
		replica.AllocateAbility: {},
		pdp.InfoAbility:         {},
	}
	if len(strgDelegation.Capabilities()) != len(expectedCapabilities) {
		return fmt.Errorf("expected exact %v capabilities, got %v", expectedCapabilities, strgDelegation.Capabilities())
	}
	for _, c := range strgDelegation.Capabilities() {
		_, ok := expectedCapabilities[c.Can()]
		if !ok {
			return fmt.Errorf("unexpected capability: %s", c.Can())
		}
		if c.With() != providerDID {
			return fmt.Errorf("capability %s has unexpected resource %s, expected: %s", c.Can(), c.With(), providerDID)
		}
	}

	return nil
}

func (s *Service) ValidateStorageTestProof(proof, providerDID string) error {
	if strings.TrimSpace(proof) == "" {
		return fmt.Errorf("proof cannot be empty")
	}

	strgDelegation, err := delegation.Parse(proof)
	if err != nil {
		return err
	}

	expiration := strgDelegation.Expiration()

	now := time.Now().Unix()
	if expiration != nil {
		if *expiration != 0 && *expiration <= int(now) {
			return fmt.Errorf("delegation expired. expiration: %d, now: %d", expiration, now)
		}
	}
	if strgDelegation.Issuer().DID().String() != providerDID {
		return fmt.Errorf("delegation issuer (%s) does not match provider DID (%s)", strgDelegation.Issuer().DID().String(), providerDID)
	}
	// For test storage, the audience should be the delegator service (not upload service)
	if strgDelegation.Audience().DID().String() != s.delegatorSigner.DID().String() {
		return fmt.Errorf("delegation audience (%s) does not match delegator service DID (%s)", strgDelegation.Audience().DID().String(), s.delegatorSigner.DID().String())
	}
	var expectedCapabilities = map[string]struct{}{
		blob.AcceptAbility:      {},
		blob.AllocateAbility:    {},
		replica.AllocateAbility: {},
		pdp.InfoAbility:         {},
	}
	if len(strgDelegation.Capabilities()) != len(expectedCapabilities) {
		return fmt.Errorf("expected exact %v capabilities, got %v", expectedCapabilities, strgDelegation.Capabilities())
	}
	for _, c := range strgDelegation.Capabilities() {
		_, ok := expectedCapabilities[c.Can()]
		if !ok {
			return fmt.Errorf("unexpected capability: %s", c.Can())
		}
		if c.With() != providerDID {
			return fmt.Errorf("capability %s has unexpected resource %s, expected: %s", c.Can(), c.With(), providerDID)
		}
	}

	return nil
}

// storeProvider stores the provider in the registry (mimicking DynamoDB table)
func (s *Service) storeProvider(session *models.OnboardingSession) error {
	now := time.Now()

	// Store provider info with Filecoin address, ProofSetID, and OperatorEmail
	providerInfo := &models.StorageProviderInfo{
		Provider:      session.DID,
		Endpoint:      session.FQDN,
		Address:       session.FilecoinAddress,
		ProofSet:      session.ProofSetID,
		OperatorEmail: session.OperatorEmail,
		Proof:         session.Proof,
		InsertedAt:    now,
		UpdatedAt:     now,
	}

	// Assuming a CreateProviderInfo method exists in the store
	// If it doesn't, you'll need to add this method to the storage interface
	if err := s.sessionStore.CreateProviderInfo(providerInfo); err != nil {
		return fmt.Errorf("failed to create provider info: %w", err)
	}

	return nil
}

// SubmitProvider handles the final submission of a provider to the persistent store
func (s *Service) SubmitProvider(sessionID string) error {
	// Get the session
	session, err := s.sessionStore.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrSessionNotFound, err.Error())
	}

	// Check if session has expired
	if time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("%w: session expired", ErrInvalidSessionState)
	}

	// Check if session is in the correct state (should be proof verified)
	if session.Status != models.StatusProofVerified {
		return fmt.Errorf("%w: expected status '%s', got '%s'",
			ErrInvalidSessionState, models.StatusProofVerified, session.Status)
	}

	// Create provider info for persistent storage
	now := time.Now()
	providerInfo := &models.StorageProviderInfo{
		Provider:      session.DID,
		Endpoint:      session.FQDN,
		Address:       session.FilecoinAddress,
		ProofSet:      session.ProofSetID,
		OperatorEmail: session.OperatorEmail,
		Proof:         session.Proof,
		InsertedAt:    now,
		UpdatedAt:     now,
	}

	// Register provider in the persistent store
	if err := s.persistedStore.RegisterProvider(providerInfo); err != nil {
		return fmt.Errorf("failed to register provider: %w", err)
	}

	// Update session status to completed
	session.Status = models.StatusCompleted
	session.UpdatedAt = now
	if err := s.sessionStore.UpdateSession(session); err != nil {
		return fmt.Errorf("failed to update session status: %w", err)
	}

	return nil
}

// getNextStep determines the next step based on current status
func (s *Service) getNextStep(status string) string {
	switch status {
	case models.StatusStarted:
		return "register-did"
	case models.StatusDIDVerified:
		return "register-fqdn"
	case models.StatusFQDNVerified:
		return "register-proof"
	case models.StatusProofVerified:
		return "completed"
	case models.StatusCompleted:
		return "completed"
	default:
		return "unknown"
	}
}

// GetDelegatorDID returns the DID of the delegator service
func (s *Service) GetDelegatorDID() string {
	return s.delegatorSigner.DID().String()
}

// StartTestStorageSession creates a new test storage session for a DID
func (s *Service) StartTestStorageSession(didStr string, urlStr string) (string, error) {
	// Parse the DID
	parsedDID, err := did.Parse(didStr)
	if err != nil {
		return "", fmt.Errorf("invalid DID format: %w", err)
	}

	// Parse and validate the URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "", fmt.Errorf("invalid URL format: %w", err)
	}

	// Ensure it's HTTPS or HTTP
	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		return "", fmt.Errorf("URL must use http or https scheme")
	}

	// Generate session ID
	sessionID := uuid.New().String()
	now := time.Now()

	// Create a test session (reusing OnboardingSession with a special status)
	session := &models.OnboardingSession{
		SessionID: sessionID,
		DID:       parsedDID.String(),
		FQDN:      urlStr,
		Status:    "test_storage_started",
		CreatedAt: now,
		UpdatedAt: now,
		ExpiresAt: now.Add(30 * time.Minute), // 30 minute timeout for test sessions
	}

	if err := s.sessionStore.CreateSession(session); err != nil {
		return "", fmt.Errorf("failed to create test session: %w", err)
	}

	return sessionID, nil
}

// GetTestStorageSession retrieves a test storage session
func (s *Service) GetTestStorageSession(sessionID string) (*models.OnboardingSession, error) {
	session, err := s.sessionStore.GetSession(sessionID)
	if err != nil {
		return nil, ErrSessionNotFound
	}

	// Check if session has expired
	if time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("%w: session expired", ErrInvalidSessionState)
	}

	// Verify this is a test storage session
	if !strings.HasPrefix(session.Status, "test_storage_") {
		return nil, fmt.Errorf("%w: not a test storage session", ErrInvalidSessionState)
	}

	return session, nil
}

// TestStorage performs the actual storage test
func (s *Service) TestStorage(sessionID string, delegationProof string) (string, error) {
	// Get the session
	session, err := s.GetTestStorageSession(sessionID)
	if err != nil {
		return "", err
	}

	// Single variable for upload size
	const testDataSizeMB = 10

	// Helper function to update progress
	updateProgress := func(step, message, details string, percentage int) {
		// Combine message and details for display since only details are shown in HTML
		fullDetails := message
		if details != "" {
			fullDetails = fmt.Sprintf("%s - %s", message, details)
		}

		progress := models.TestProgress{
			Step:       step,
			Message:    message,
			Details:    fullDetails,
			Percentage: percentage,
		}
		progressJSON, _ := json.Marshal(progress)
		// Re-fetch the session to ensure we have the latest version
		currentSession, err := s.sessionStore.GetSession(sessionID)
		if err != nil {
			log.Errorw("Failed to get session for progress update", "error", err)
			return
		}
		currentSession.TestProgress = string(progressJSON)
		currentSession.UpdatedAt = time.Now()
		if err := s.sessionStore.UpdateSession(currentSession); err != nil {
			log.Errorw("Failed to update session progress", "error", err)
		}
		// Update our local session reference
		session = currentSession
		// Add a small delay to ensure the update is persisted
		time.Sleep(100 * time.Millisecond)
	}

	// Validate the delegation
	updateProgress("validating", "Validating delegation proof", "", 10)
	if err := s.ValidateStorageTestProof(delegationProof, session.DID); err != nil {
		// Update progress with error before returning
		updateProgress("error", "Delegation validation failed", err.Error(), 10)
		return "", fmt.Errorf("delegation validation failed: %w", err)
	}
	updateProgress("validating", "Delegation proof is valid", "Ready to proceed with storage test", 15)

	// Update session status
	session.Status = "test_storage_validated"
	session.UpdatedAt = time.Now()
	if err := s.sessionStore.UpdateSession(session); err != nil {
		log.Errorw("Failed to update session status", "error", err)
	}

	log.Infow("TestStorage called", "session_id", sessionID, "did", session.DID)

	nodeDID, err := did.Parse(session.DID)
	if err != nil {
		updateProgress("error", "Failed to parse DID", err.Error(), 20)
		return "", err
	}
	nodeURL, err := url.Parse(session.FQDN)
	if err != nil {
		updateProgress("error", "Failed to parse URL", err.Error(), 20)
		return "", err
	}
	nodeProof, err := delegation.Parse(delegationProof)
	if err != nil {
		updateProgress("error", "Failed to parse delegation proof", err.Error(), 20)
		return "", err
	}
	cl, err := client.NewClient(client.Config{
		ID:             s.delegatorSigner,
		StorageNodeID:  nodeDID,
		StorageNodeURL: *nodeURL,
		StorageProof:   delegation.FromDelegation(nodeProof),
	})
	if err != nil {
		updateProgress("error", "Failed to create storage client", err.Error(), 20)
		return "", fmt.Errorf("failed to create client: %w", err)
	}

	// Generate test data
	updateProgress("generating", "Generating test data", fmt.Sprintf("Creating %dMB test file", testDataSizeMB), 25)
	blobData := generatePiriString(testDataSizeMB)
	digest, err := sha256.Hasher.Sum(blobData)
	if err != nil {
		updateProgress("error", "Failed to compute data hash", err.Error(), 30)
		return "", err
	}

	// Allocate space
	updateProgress("allocating", "Allocating space on your piri node", fmt.Sprintf("Requesting %dMB of storage", testDataSizeMB), 40)
	address, err := cl.BlobAllocate(nodeDID, digest.Bytes(), uint64(len(blobData)), cidlink.Link{Cid: cid.NewCidV1(cid.Raw, digest.Bytes())})
	if err != nil {
		updateProgress("error", "Failed to allocate storage", err.Error(), 40)
		return "", err
	}

	var downloadURL string
	var avgSpeedGbps float64
	if address != nil {
		// Upload data
		updateProgress("uploading", fmt.Sprintf("Uploading data to %s", address.URL.String()), "Starting upload...", 60)

		// Track upload start time for speed calculation
		uploadStartTime := time.Now()
		var lastBytesRead int64
		var lastUpdateTime = uploadStartTime

		// Create progress reader that updates progress from 60% to 80% during upload
		pgr := newProgressReader(
			bytes.NewReader(blobData),
			int64(len(blobData)),
			func(bytesRead, totalBytes int64) {
				// Calculate progress between 60% and 80%
				uploadPercent := float64(bytesRead) / float64(totalBytes)
				overallPercent := 60 + int(uploadPercent*20) // 60% to 80%

				// Calculate upload speed
				now := time.Now()
				timeSinceLastUpdate := now.Sub(lastUpdateTime).Seconds()
				bytesSinceLastUpdate := bytesRead - lastBytesRead

				var speedStr string
				if timeSinceLastUpdate > 0 {
					bytesPerSecond := float64(bytesSinceLastUpdate) / timeSinceLastUpdate
					// Convert to Gigabits per second (1 byte = 8 bits, 1 Gbit = 1,000,000,000 bits)
					gbitsPerSecond := (bytesPerSecond * 8) / 1_000_000_000
					speedStr = fmt.Sprintf(" @ %.3f Gbps", gbitsPerSecond)
				}

				// Update tracking variables
				lastBytesRead = bytesRead
				lastUpdateTime = now

				// Update progress with bytes uploaded and speed
				mbUploaded := float64(bytesRead) / (1024 * 1024)
				mbTotal := float64(totalBytes) / (1024 * 1024)
				percentComplete := int(uploadPercent * 100)
				details := fmt.Sprintf("Uploaded %.1f MB of %.1f MB (%d%%)%s", mbUploaded, mbTotal, percentComplete, speedStr)
				updateProgress("uploading", fmt.Sprintf("Uploading data to %s", address.URL.String()), details, overallPercent)
			},
		)

		req, err := http.NewRequest(http.MethodPut, address.URL.String(), pgr)
		if err != nil {
			return "", fmt.Errorf("uploading blob: %w", err)
		}
		req.Header = address.Headers
		req.ContentLength = int64(len(blobData)) // Set content length for proper progress tracking
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("sending blob: %w", err)
		}
		defer res.Body.Close()
		if res.StatusCode >= 300 || res.StatusCode < 200 {
			resData, err := io.ReadAll(res.Body)
			if err != nil {
				return "", fmt.Errorf("reading response body: %w", err)
			}
			return "", fmt.Errorf("unsuccessful put, status: %s, message: %s", res.Status, string(resData))
		}

		// Calculate total upload time and average speed
		uploadEndTime := time.Now()
		uploadDuration := uploadEndTime.Sub(uploadStartTime).Seconds()

		if uploadDuration > 0 {
			totalBytesPerSecond := float64(len(blobData)) / uploadDuration
			avgSpeedGbps = (totalBytesPerSecond * 8) / 1_000_000_000
		}

		// Accept blob and aggregate
		updateProgress("aggregating", "Aggregating data into PDP", "Processing uploaded data for proof generation", 80)

		// Create a channel to signal when BlobAccept is done
		done := make(chan struct{})
		var blobResult *client.BlobAcceptResult
		var acceptErr error

		// Run BlobAccept in a goroutine
		go func() {
			blobResult, acceptErr = cl.BlobAccept(nodeDID, digest.Bytes(), uint64(len(blobData)), cidlink.Link{Cid: cid.NewCidV1(cid.Raw, digest.Bytes())})
			close(done)
		}()

		// Update progress with animated dots while waiting
		progressTicker := time.NewTicker(500 * time.Millisecond)
		defer progressTicker.Stop()

		dots := 0
		startTime := time.Now()
		for {
			select {
			case <-done:
				// BlobAccept completed
				if acceptErr != nil {
					return "", fmt.Errorf("accepting blob: %w", acceptErr)
				}
				// Final update before moving on
				updateProgress("aggregating", "Aggregating data into PDP", "Processing completed", 90)
				goto acceptComplete
			case <-progressTicker.C:
				// Update progress with animated dots and elapsed time
				dots = (dots + 1) % 4
				dotStr := strings.Repeat(".", dots)
				elapsed := time.Since(startTime).Round(time.Second)
				details := fmt.Sprintf("Processing uploaded data for proof generation%s (%s elapsed)", dotStr, elapsed)
				updateProgress("aggregating", "Aggregating data into PDP", details, 80)
			}
		}
	acceptComplete:

		if len(blobResult.LocationCommitment.Location) > 0 {
			downloadURL = blobResult.LocationCommitment.Location[0].String()
			log.Infof("uploaded blob available at: %s\n", downloadURL)
		}
		if blobResult.PDPAccept != nil {
			log.Infof("submitted for PDP aggregation: %s\n", blobResult.PDPAccept.Piece.Link().String())
		}

		// Create structured test result with upload statistics
		testStats := struct {
			DownloadURL    string  `json:"download_url"`
			UploadSizeMB   int     `json:"upload_size_mb"`
			AvgSpeedGbps   float64 `json:"avg_speed_gbps"`
			UploadDuration float64 `json:"upload_duration_seconds"`
		}{
			DownloadURL:    downloadURL,
			UploadSizeMB:   testDataSizeMB,
			AvgSpeedGbps:   avgSpeedGbps,
			UploadDuration: uploadDuration,
		}

		// Store the stats in the TestResult as JSON for the template to parse
		statsJSON, _ := json.Marshal(testStats)
		session.TestResult = string(statsJSON)
	}

	// Update final result with download URL and stats
	finalProgress := models.TestProgress{
		Step:        "completed",
		Message:     "Storage test completed successfully",
		Details:     "Storage test completed successfully - Your node is properly configured to accept storage requests.",
		DownloadURL: downloadURL,
		Percentage:  100,
	}
	progressJSON, _ := json.Marshal(finalProgress)
	session.TestProgress = string(progressJSON)
	session.Status = "test_storage_completed"
	session.UpdatedAt = time.Now()
	if err := s.sessionStore.UpdateSession(session); err != nil {
		log.Errorw("Failed to update session with final result", "error", err)
	}

	return fmt.Sprintf("Success! Test completed. Download URL: %s | Size: %dMB | Avg Speed: %.3f Gbps", downloadURL, testDataSizeMB, avgSpeedGbps), nil
}

func generatePiriString(sizeInMB int) []byte {
	targetSize := sizeInMB * 1024 * 1024
	randomSuffix := 64 // 64 random bytes at the end
	piriSize := targetSize - randomSuffix

	// Calculate how many complete "piri" strings we need for the piri section
	piriLen := len("piri")
	completeRepeats := piriSize / piriLen
	remainder := piriSize % piriLen

	// Build the string
	var builder strings.Builder
	builder.Grow(targetSize) // Pre-allocate capacity

	// Add complete "piri" repeats
	piriString := strings.Repeat("piri", completeRepeats)
	builder.WriteString(piriString)

	// Add partial "piri" if needed to fill remaining piri section
	if remainder > 0 {
		builder.WriteString("piri"[:remainder])
	}

	// Generate and append 64 random bytes
	randomBytes := make([]byte, randomSuffix)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate random bytes: %v", err))
	}

	builder.Write(randomBytes)

	return []byte(builder.String())
}
