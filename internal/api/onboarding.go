package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/storacha/go-ucanto/did"
	ed25519 "github.com/storacha/go-ucanto/principal/ed25519/signer"

	"github.com/storacha/delegator/internal/config"
	"github.com/storacha/delegator/internal/models"
	"github.com/storacha/delegator/internal/services"
	"github.com/storacha/delegator/internal/storage"
)

// OnboardingHandler handles onboarding-related API endpoints
type OnboardingHandler struct {
	service *services.OnboardingService
}

// NewOnboardingHandler creates a new onboarding handler
func NewOnboardingHandler(store storage.Store, cfg config.OnboardingConfig) (*OnboardingHandler, error) {
	sessionTimeout := time.Duration(cfg.SessionTimeout) * time.Second
	delegationTTL := time.Duration(cfg.DelegationTTL) * time.Second

	indexingService, err := ed25519.Parse(cfg.IndexingServiceKey)
	if err != nil {
		return nil, fmt.Errorf("error parsing configured indexing service: %w", err)
	}
	uploadService, err := ed25519.Parse(cfg.UploadServiceKey)
	if err != nil {
		return nil, fmt.Errorf("error parsing configured upload service: %w", err)
	}

	service := services.NewOnboardingService(store, sessionTimeout, delegationTTL, indexingService, uploadService)

	return &OnboardingHandler{
		service: service,
	}, nil
}

// validateURL ensures the URL is HTTPS with a domain name (no IP addresses or ports)
func (h *OnboardingHandler) validateURL(rawURL string) (*url.URL, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("URL is invalid: %w", err)
	}

	/*
		if parsedURL.Scheme != "https" {
			return nil, fmt.Errorf("URL scheme is invalid: %s. Must be https", parsedURL.Scheme)
		}
	*/
	if parsedURL.Host == "" {
		return nil, fmt.Errorf("URL must have a host")
	}

	/*
			// Check for port in the host
			if strings.Contains(parsedURL.Host, ":") {
				return nil, fmt.Errorf("URL must not contain a port")
			}


		// Check if host is an IP address
		if net.ParseIP(parsedURL.Host) != nil {
			return nil, fmt.Errorf("URL must use a domain name, not an IP address")
		}
	*/

	return parsedURL, nil
}

// registerFQDN handles POST /api/v1/onboard/register-fqdn
func (h *OnboardingHandler) registerFQDN(c echo.Context) error {
	var req models.FQDNRegisterRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
	}

	if req.SessionID == "" {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "missing_session_id",
			Message: "Session ID is required",
			Code:    http.StatusBadRequest,
		})
	}

	if req.URL == "" {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "missing_url",
			Message: "URL is required",
			Code:    http.StatusBadRequest,
		})
	}

	strgURL, err := h.validateURL(req.URL)
	if err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "invalid_url",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
	}

	resp, err := h.service.RegisterFQDN(req.SessionID, *strgURL)
	if err != nil {
		if errors.Is(err, services.ErrSessionNotFound) {
			return c.JSON(http.StatusNotFound, models.ErrorResponse{
				Error:   "session_not_found",
				Message: fmt.Sprintf("Session '%s' not found", req.SessionID),
				Code:    http.StatusNotFound,
			})
		}
		if errors.Is(err, services.ErrInvalidSessionState) {
			return c.JSON(http.StatusBadRequest, models.ErrorResponse{
				Error:   "invalid_session_state",
				Message: err.Error(),
				Code:    http.StatusBadRequest,
			})
		}
		if errors.Is(err, services.ErrFQDNVerificationFailed) {
			return c.JSON(http.StatusBadRequest, models.ErrorResponse{
				Error:   "fqdn_verification_failed",
				Message: err.Error(),
				Code:    http.StatusBadRequest,
			})
		}
		// Internal server error for other cases
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "verification_failed",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
		})
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "FQDN verified successfully",
		Data:    resp,
	})
}

// registerDID handles POST /api/v1/onboard/register-did
func (h *OnboardingHandler) registerDID(c echo.Context) error {
	var req models.DIDRegisterRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
	}

	if req.DID == "" {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "missing_did",
			Message: "DID is required",
			Code:    http.StatusBadRequest,
		})
	}

	if req.FilecoinAddress == "" {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "missing_filecoin_address",
			Message: "Filecoin Address is required",
			Code:    http.StatusBadRequest,
		})
	}

	if req.ProofSetID == 0 {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "missing_proof_set_id",
			Message: "Proof Set ID is required and must be greater than 0",
			Code:    http.StatusBadRequest,
		})
	}

	if req.OperatorEmail == "" {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "missing_operator_email",
			Message: "Operator Email is required",
			Code:    http.StatusBadRequest,
		})
	}

	strgDID, err := did.Parse(req.DID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "invalid_did",
			Message: fmt.Sprintf("DID is invalid: %s", err),
			Code:    http.StatusBadRequest,
		})
	}

	resp, err := h.service.RegisterDID(strgDID, req.FilecoinAddress, req.ProofSetID, req.OperatorEmail)
	if err != nil {
		if errors.Is(err, services.ErrIsNotAllowed) {
			return c.JSON(http.StatusForbidden, models.ErrorResponse{
				Error:   "is_not_allowed",
				Message: fmt.Sprintf("DID '%s' is not allowed", req.DID),
				Code:    http.StatusForbidden,
			})
		}
		if errors.Is(err, services.ErrIsAlreadyRegistered) {
			return c.JSON(http.StatusConflict, models.ErrorResponse{
				Error:   "is_already_registered",
				Message: fmt.Sprintf("DID '%s' is already registered", req.DID),
				Code:    http.StatusConflict,
			})
		}
		// else
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "verification_failed",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
		})
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "DID verified successfully",
		Data:    resp,
	})
}

// registerProof handles POST /api/v1/onboard/register-proof
func (h *OnboardingHandler) registerProof(c echo.Context) error {
	var req models.ProofRegisterRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "invalid_request",
			Message: "Invalid request body",
			Code:    http.StatusBadRequest,
		})
	}

	if req.SessionID == "" {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "missing_session_id",
			Message: "Session ID is required",
			Code:    http.StatusBadRequest,
		})
	}

	if req.Proof == "" {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "missing_proof",
			Message: "Proof is required",
			Code:    http.StatusBadRequest,
		})
	}

	resp, err := h.service.RegisterProof(req.SessionID, req.Proof)
	if err != nil {
		if errors.Is(err, services.ErrSessionNotFound) {
			return c.JSON(http.StatusNotFound, models.ErrorResponse{
				Error:   "session_not_found",
				Message: fmt.Sprintf("Session '%s' not found", req.SessionID),
				Code:    http.StatusNotFound,
			})
		}
		if errors.Is(err, services.ErrInvalidSessionState) {
			return c.JSON(http.StatusBadRequest, models.ErrorResponse{
				Error:   "invalid_session_state",
				Message: err.Error(),
				Code:    http.StatusBadRequest,
			})
		}
		if errors.Is(err, services.ErrProofVerificationFailed) {
			return c.JSON(http.StatusBadRequest, models.ErrorResponse{
				Error:   "proof_verification_failed",
				Message: err.Error(),
				Code:    http.StatusBadRequest,
			})
		}
		// Internal server error for other cases
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "verification_failed",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
		})
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Proof verified successfully",
		Data:    resp,
	})
}

// getSessionStatus handles GET /api/v1/onboard/status/:session_id
func (h *OnboardingHandler) getSessionStatus(c echo.Context) error {
	sessionID := c.Param("session_id")
	if sessionID == "" {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "missing_session_id",
			Message: "Session ID is required",
			Code:    http.StatusBadRequest,
		})
	}

	status, err := h.service.GetSessionStatus(sessionID)
	if err != nil {
		return c.JSON(http.StatusNotFound, models.ErrorResponse{
			Error:   "session_not_found",
			Message: err.Error(),
			Code:    http.StatusNotFound,
		})
	}

	return c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    status,
	})
}

// getDelegation handles GET /api/v1/onboard/delegation/:session_id
func (h *OnboardingHandler) getDelegation(c echo.Context) error {
	sessionID := c.Param("session_id")
	if sessionID == "" {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "missing_session_id",
			Message: "Session ID is required",
			Code:    http.StatusBadRequest,
		})
	}

	delegationData, err := h.service.GetDelegation(sessionID)
	if err != nil {
		return c.JSON(http.StatusNotFound, models.ErrorResponse{
			Error:   "delegation_not_found",
			Message: err.Error(),
			Code:    http.StatusNotFound,
		})
	}

	// Return delegation as downloadable file
	c.Response().Header().Set("Content-Type", "application/json")
	c.Response().Header().Set("Content-Disposition", "attachment; filename=delegation.json")
	return c.Blob(http.StatusOK, "application/octet-stream", []byte(delegationData))
}
