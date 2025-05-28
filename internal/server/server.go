package server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/storacha/delegator/internal/api"
	"github.com/storacha/delegator/internal/config"
	"github.com/storacha/delegator/internal/storage"
)

// Server represents the HTTP server instance
type Server struct {
	echo   *echo.Echo
	config *config.Config
	store  storage.Store
}

type Option func(*serverOptions)

func WithStore(store storage.Store) Option {
	return func(s *serverOptions) {
		s.store = store
	}
}

type serverOptions struct {
	store storage.Store
}

// New creates a new server instance with the provided configuration
func New(cfg *config.Config, opts ...Option) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	options := &serverOptions{
		store: storage.NewMemoryStore(),
	}
	for _, opt := range opts {
		opt(options)
	}

	// Create Echo instance
	e := echo.New()
	e.HideBanner = true

	// Configure middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())
	e.Use(middleware.RequestID())

	// Configure server timeouts
	e.Server.ReadTimeout = cfg.Server.ReadTimeout
	e.Server.WriteTimeout = cfg.Server.WriteTimeout

	// Initialize API routes
	if err := api.RegisterRoutes(e, cfg, options.store); err != nil {
		return nil, fmt.Errorf("failed to register routes: %w", err)
	}

	svr := &Server{
		echo:   e,
		config: cfg,
		store:  options.store,
	}

	return svr, nil
}

// Start starts the HTTP server
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port)
	fmt.Printf("Starting HTTP server on %s\n", addr)

	if err := s.echo.Start(addr); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server start failed: %w", err)
	}

	return nil
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	fmt.Println("Shutting down server...")

	if err := s.echo.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	fmt.Println("Server exited")
	return nil
}

// Echo returns the underlying Echo instance for advanced configuration
func (s *Server) Echo() *echo.Echo {
	return s.echo
}

func (s *Server) Store() storage.Store {
	return s.store
}
