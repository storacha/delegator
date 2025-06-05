package storage

import (
	"fmt"
	"sync"
	"time"

	logging "github.com/ipfs/go-log"

	"github.com/storacha/delegator/internal/models"
)

var log = logging.Logger("storage/memory")

// MemoryStore provides in-memory storage that mimics DynamoDB interfaces
type MemoryStore struct {
	allowlist    map[string]*models.DIDAllowlist
	sessions     map[string]*models.OnboardingSession
	providers    map[string]*models.StorageProvider
	providerInfo map[string]*models.StorageProviderInfo
	mu           sync.RWMutex
}

// NewMemoryStore creates a new in-memory store that implements both SessionStore and PersistentStore
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		allowlist:    make(map[string]*models.DIDAllowlist),
		sessions:     make(map[string]*models.OnboardingSession),
		providers:    make(map[string]*models.StorageProvider),
		providerInfo: make(map[string]*models.StorageProviderInfo),
	}
}

// DID Allowlist operations
// IsAllowedDID checks if a DID is in the allowlist (PersistentStore interface)
func (m *MemoryStore) IsAllowedDID(did string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.allowlist[did]
	return exists, nil
}

// AddAllowedDID adds a DID to the allowlist (PersistentStore interface)
func (m *MemoryStore) AddAllowedDID(did string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.allowlist[did] = &models.DIDAllowlist{
		DID:     did,
		AddedBy: "system",
		AddedAt: time.Now(),
		Notes:   "Added via API",
	}

	return nil
}

// Onboarding session operations
func (m *MemoryStore) CreateSession(session *models.OnboardingSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Debugw("Creating session",
		"session_id", session.SessionID,
		"did", session.DID)

	m.sessions[session.SessionID] = session

	// Dump all current sessions for debugging
	log.Debugw("Current sessions in memory store", "count", len(m.sessions))
	for id, s := range m.sessions {
		log.Debugw("Session details",
			"session_id", id,
			"did", s.DID,
			"status", s.Status,
			"expires_at", s.ExpiresAt.Format(time.RFC3339))
	}

	return nil
}

func (m *MemoryStore) GetSession(sessionID string) (*models.OnboardingSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	log.Debugw("Looking for session", "session_id", sessionID)

	// Dump all current sessions for debugging
	log.Debugw("Available sessions in memory store", "count", len(m.sessions))
	for id, s := range m.sessions {
		log.Debugw("Session details",
			"session_id", id,
			"did", s.DID,
			"status", s.Status,
			"expires_at", s.ExpiresAt.Format(time.RFC3339))
	}

	session, exists := m.sessions[sessionID]
	if !exists {
		log.Debugw("Session not found", "session_id", sessionID)
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		log.Debugw("Session expired",
			"session_id", sessionID,
			"expired_at", session.ExpiresAt.Format(time.RFC3339))
		return nil, fmt.Errorf("session expired: %s", sessionID)
	}

	log.Debugw("Found session",
		"session_id", session.SessionID,
		"did", session.DID,
		"status", session.Status)

	return session, nil
}

func (m *MemoryStore) UpdateSession(session *models.OnboardingSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[session.SessionID]; !exists {
		return fmt.Errorf("session not found: %s", session.SessionID)
	}

	session.UpdatedAt = time.Now()
	m.sessions[session.SessionID] = session
	return nil
}

func (m *MemoryStore) GetSessionByDID(did string) (*models.OnboardingSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, session := range m.sessions {
		if session.DID == did && time.Now().Before(session.ExpiresAt) {
			return session, nil
		}
	}
	return nil, fmt.Errorf("no active session found for DID: %s", did)
}

// IsRegisteredDID checks if a DID is registered as a provider (implements PersistentStore interface)
func (m *MemoryStore) IsRegisteredDID(did string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.providerInfo[did]
	return exists, nil
}

func (m *MemoryStore) CreateProvider(provider *models.StorageProvider) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.providers[provider.Provider] = provider
	return nil
}

// Provider info operations
func (m *MemoryStore) CreateProviderInfo(info *models.StorageProviderInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.providerInfo[info.Provider] = info
	return nil
}

// RegisterProvider registers a new provider (implements PersistentStore interface)
func (m *MemoryStore) RegisterProvider(provider *models.StorageProviderInfo) error {
	return m.CreateProviderInfo(provider)
}
