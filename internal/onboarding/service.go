package onboarding

import (
	"context"
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
	logging "github.com/ipfs/go-log"
	"github.com/storacha/go-libstoracha/capabilities/blob"
	"github.com/storacha/go-libstoracha/capabilities/blob/replica"
	"github.com/storacha/go-libstoracha/capabilities/claim"
	"github.com/storacha/go-libstoracha/capabilities/pdp"
	"github.com/storacha/go-ucanto/core/delegation"
	"github.com/storacha/go-ucanto/did"
	"github.com/storacha/go-ucanto/principal"
	"github.com/storacha/go-ucanto/ucan"

	"github.com/storacha/delegator/internal/config"
	"github.com/storacha/delegator/internal/models"
	"github.com/storacha/delegator/internal/storage"
)

var log = logging.Logger("service/onboarding")

// OnboardingService handles WSP onboarding logic
type Service struct {
	sessionStore   storage.SessionStore
	persistedStore storage.PersistentStore

	sessionTimeout     time.Duration
	domainCheckTimeout time.Duration

	delegatorSigner      principal.Signer
	indexingServiceProof delegation.Proof
	uploadServiceDID     did.DID
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
		sessionStore:         storage.NewMemoryStore(),
		persistedStore:       storage.NewMemoryStore(),
		sessionTimeout:       cfg.SessionTimeout,
		domainCheckTimeout:   cfg.FQDNVerificationTimeout,
		delegatorSigner:      delegatorSigner,
		indexingServiceProof: indexerProof,
		uploadServiceDID:     uploadServiceDID,
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
				s.delegatorSigner.DID().String(),
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
