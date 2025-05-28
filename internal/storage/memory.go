package storage

import (
	"fmt"
	"sync"
	"time"

	"github.com/storacha/delegator/internal/models"
)

// MemoryStore provides in-memory storage that mimics DynamoDB interfaces
type MemoryStore struct {
	allowlist    map[string]*models.DIDAllowlist
	sessions     map[string]*models.OnboardingSession
	providers    map[string]*models.StorageProvider
	providerInfo map[string]*models.StorageProviderInfo
	mu           sync.RWMutex
}

// NewMemoryStore creates a new in-memory store
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		allowlist:    make(map[string]*models.DIDAllowlist),
		sessions:     make(map[string]*models.OnboardingSession),
		providers:    make(map[string]*models.StorageProvider),
		providerInfo: make(map[string]*models.StorageProviderInfo),
	}
}

// DID Allowlist operations
func (m *MemoryStore) IsAllowedDID(did string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.allowlist[did]
	return exists
}

func (m *MemoryStore) AddAllowedDID(entry *models.DIDAllowlist) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allowlist[entry.DID] = entry
	return nil
}

func (m *MemoryStore) RemoveAllowedDID(did string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.allowlist, did)
	return nil
}

func (m *MemoryStore) ListAllowedDIDs() ([]*models.DIDAllowlist, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*models.DIDAllowlist, 0, len(m.allowlist))
	for _, entry := range m.allowlist {
		result = append(result, entry)
	}
	return result, nil
}

// Onboarding session operations
func (m *MemoryStore) CreateSession(session *models.OnboardingSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	fmt.Printf("DEBUG MemoryStore.CreateSession: Creating session with ID: %s, DID: %s\n", 
		session.SessionID, session.DID)
	
	m.sessions[session.SessionID] = session
	
	// Dump all current sessions for debugging
	fmt.Println("DEBUG MemoryStore: Current sessions:")
	for id, s := range m.sessions {
		fmt.Printf("  - %s: DID=%s, Status=%s, Expires=%s\n", 
			id, s.DID, s.Status, s.ExpiresAt.Format(time.RFC3339))
	}
	
	return nil
}

func (m *MemoryStore) GetSession(sessionID string) (*models.OnboardingSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	fmt.Printf("DEBUG MemoryStore.GetSession: Looking for session ID: %s\n", sessionID)
	
	// Dump all current sessions for debugging
	fmt.Println("DEBUG MemoryStore: Available sessions:")
	for id, s := range m.sessions {
		fmt.Printf("  - %s: DID=%s, Status=%s, Expires=%s\n", 
			id, s.DID, s.Status, s.ExpiresAt.Format(time.RFC3339))
	}

	session, exists := m.sessions[sessionID]
	if !exists {
		fmt.Printf("DEBUG MemoryStore.GetSession: Session not found: %s\n", sessionID)
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		fmt.Printf("DEBUG MemoryStore.GetSession: Session expired: %s, expired at %s\n", 
			sessionID, session.ExpiresAt.Format(time.RFC3339))
		return nil, fmt.Errorf("session expired: %s", sessionID)
	}

	fmt.Printf("DEBUG MemoryStore.GetSession: Found session: ID=%s, DID=%s, Status=%s\n", 
		session.SessionID, session.DID, session.Status)
	
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

// Provider operations
func (m *MemoryStore) IsProviderRegistered(did string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.providers[did]
	return exists
}

func (m *MemoryStore) CreateProvider(provider *models.StorageProvider) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.providers[provider.Provider] = provider
	return nil
}

func (m *MemoryStore) GetProvider(did string) (*models.StorageProvider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	provider, exists := m.providers[did]
	if !exists {
		return nil, fmt.Errorf("provider not found: %s", did)
	}
	return provider, nil
}

func (m *MemoryStore) ListProviders() ([]*models.StorageProvider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*models.StorageProvider, 0, len(m.providers))
	for _, provider := range m.providers {
		result = append(result, provider)
	}
	return result, nil
}

// Provider info operations
func (m *MemoryStore) CreateProviderInfo(info *models.StorageProviderInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.providerInfo[info.Provider] = info
	return nil
}

func (m *MemoryStore) GetProviderInfo(did string) (*models.StorageProviderInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	info, exists := m.providerInfo[did]
	if !exists {
		return nil, fmt.Errorf("provider info not found: %s", did)
	}
	return info, nil
}

// SetAllowedDIDs populates the store with config data
func (m *MemoryStore) SetAllowedDIDs(allowedDIDs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for _, did := range allowedDIDs {
		m.allowlist[did] = &models.DIDAllowlist{
			DID:     did,
			AddedBy: "config",
			AddedAt: now,
			Notes:   "Loaded from configuration",
		}
	}

	return nil
}
