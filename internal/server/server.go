package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/fx"

	"github.com/storacha/delegator/internal/config"
	"github.com/storacha/delegator/internal/handlers"
)

type Server struct {
	echo     *echo.Echo
	config   *config.Config
	handlers *handlers.Handlers
}

func NewServer(cfg *config.Config, h *handlers.Handlers) *Server {
	e := echo.New()
	e.HideBanner = true

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.RequestID())

	return &Server{
		echo:     e,
		config:   cfg,
		handlers: h,
	}
}

func (s *Server) setupRoutes() {
	s.echo.GET("/health", s.handlers.HealthCheck)
	s.echo.GET("/", s.handlers.Root)
	s.echo.PUT("/registrar/register-node", s.handlers.Register)
	s.echo.GET("/registrar/request-proof", s.handlers.RequestProof)
	s.echo.GET("/registrar/is-registered", s.handlers.IsRegistered)
	s.echo.POST("/benchmark/upload", s.handlers.BenchmarkUpload)
	s.echo.POST("/benchmark/download", s.handlers.BenchmarkDownload)
}

func Start(lc fx.Lifecycle, s *Server) {
	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			s.setupRoutes()

			go func() {
				addr := s.config.Server.Address()
				fmt.Printf("Starting server on %s\n", addr)
				if err := s.echo.Start(addr); err != nil && !errors.Is(err, http.ErrServerClosed) {
					fmt.Printf("Server error: %v\n", err)
				}
			}()

			return nil
		},
		OnStop: func(ctx context.Context) error {
			fmt.Println("Shutting down server...")
			return s.echo.Shutdown(ctx)
		},
	})
}
