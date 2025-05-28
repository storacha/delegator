package storage

import "github.com/storacha/delegator/internal/models"

// OnboardingStore defines the interface for onboarding session storage
type OnboardingStore interface {
	CreateSession(session *models.OnboardingSession) error
	GetSession(sessionID string) (*models.OnboardingSession, error)
	UpdateSession(session *models.OnboardingSession) error
	GetSessionByDID(did string) (*models.OnboardingSession, error)
	SetAllowedDIDs(allowedDIDs []string) error
}

// AllowlistStore defines the interface for DID allowlist storage
type AllowlistStore interface {
	IsAllowedDID(did string) bool
	AddAllowedDID(entry *models.DIDAllowlist) error
	RemoveAllowedDID(did string) error
	ListAllowedDIDs() ([]*models.DIDAllowlist, error)
}

// ProviderStore defines the interface for provider storage
type ProviderStore interface {
	IsProviderRegistered(did string) bool
	CreateProvider(provider *models.StorageProvider) error
	GetProvider(did string) (*models.StorageProvider, error)
	ListProviders() ([]*models.StorageProvider, error)
}

// ProviderInfoStore defines the interface for provider info storage
type ProviderInfoStore interface {
	CreateProviderInfo(info *models.StorageProviderInfo) error
	GetProviderInfo(did string) (*models.StorageProviderInfo, error)
}

// Store combines all storage interfaces
type Store interface {
	OnboardingStore
	AllowlistStore
	ProviderStore
	ProviderInfoStore
}
