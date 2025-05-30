package server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"
	logging "github.com/ipfs/go-log"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/storacha/delegator/internal/api"
	"github.com/storacha/delegator/internal/config"
	"github.com/storacha/delegator/internal/storage"
)

var log = logging.Logger("server")

// Server represents the HTTP server instance
type Server struct {
	echo           *echo.Echo
	config         *config.Config
	sessionStore   storage.SessionStore
	persistedStore storage.PersistentStore
}

// New creates a new server instance with the provided configuration
func New(cfg *config.Config) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	dynamoStore, err := storage.NewDynamoDBStore(cfg.Dynamo)
	if err != nil {
		return nil, err
	}
	if len(cfg.Onboarding.AllowList) > 0 {
		if err := dynamoStore.AddAllowedDID(cfg.Onboarding.AllowList[0]); err != nil {
			return nil, err
		}
	}

	// Create Echo instance
	e := echo.New()
	e.HideBanner = true

	// Configure middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())
	e.Use(middleware.RequestID())

	// Configure session middleware with proper settings
	cookieStore := sessions.NewCookieStore([]byte(cfg.Server.SessionKey))
	cookieStore.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 1 week
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
	}
	e.Use(session.Middleware(cookieStore))

	// Log debug message about session configuration
	log.Debugw("Session middleware configured", "key_length", len(cfg.Server.SessionKey))

	e.Server.ReadTimeout = cfg.Server.ReadTimeout
	e.Server.ReadHeaderTimeout = cfg.Server.ReadTimeout
	e.Server.IdleTimeout = cfg.Server.ReadTimeout
	e.Server.WriteTimeout = cfg.Server.WriteTimeout

	// Initialize API routes
	sessionStore := storage.NewMemoryStore()
	if err := api.RegisterRoutes(e, cfg, sessionStore, dynamoStore); err != nil {
		return nil, fmt.Errorf("failed to register routes: %w", err)
	}

	svr := &Server{
		echo:           e,
		config:         cfg,
		sessionStore:   sessionStore,
		persistedStore: dynamoStore,
	}

	return svr, nil
}

// Start starts the HTTP server
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port)
	log.Infow("Starting HTTP server", "address", addr)

	if err := s.echo.Start(addr); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server start failed: %w", err)
	}

	return nil
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	log.Infow("Shutting down server")

	if err := s.echo.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	log.Infow("Server exited")
	return nil
}

// Echo returns the underlying Echo instance for advanced configuration
func (s *Server) Echo() *echo.Echo {
	return s.echo
}

// SessionStore returns the session store
func (s *Server) SessionStore() storage.SessionStore {
	return s.sessionStore
}

// PersistentStore returns the persistent store
func (s *Server) PersistentStore() storage.PersistentStore {
	return s.persistedStore
}
