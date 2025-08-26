package handlers

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/ethereum/go-ethereum/common"
	"github.com/labstack/echo/v4"
	"github.com/storacha/go-ucanto/core/delegation"
	"github.com/storacha/go-ucanto/did"
	"github.com/storacha/piri/delegator/internal/services/benchmark"
	"github.com/storacha/piri/delegator/internal/services/registrar"
)

type Handlers struct {
	service          *registrar.Service
	benchmarkService *benchmark.Service
}

func NewHandlers(svc *registrar.Service, benchmarkSvc *benchmark.Service) *Handlers {
	return &Handlers{
		service:          svc,
		benchmarkService: benchmarkSvc,
	}
}

func (h *Handlers) HealthCheck(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{
		"status": "healthy",
	})
}

func (h *Handlers) Root(c echo.Context) error {
	return c.String(http.StatusOK, "hello")
}

type RegisterRequest struct {
	DID           string `json:"did"`
	OwnerAddress  string `json:"owner_address"`
	ProofSetID    uint64 `json:"proof_set_id"`
	OperatorEmail string `json:"operator_email"`
	PublicURL     string `json:"public_url"`
	Proof         string `json:"proof"`
}

func (h *Handlers) Register(c echo.Context) error {
	var req RegisterRequest
	if err := c.Bind(&req); err != nil {
		return c.String(http.StatusBadRequest, "invalid request body")
	}

	// parse and validate request
	operator, err := did.Parse(req.DID)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid DID")
	}
	if !common.IsHexAddress(req.OwnerAddress) {
		return c.String(http.StatusBadRequest, "invalid OwnerAddress")
	}
	endpoint, err := url.Parse(req.PublicURL)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid PublicURL")
	}

	if err := h.service.Register(c.Request().Context(), registrar.RegisterParams{
		DID:           operator,
		OwnerAddress:  common.HexToAddress(req.OwnerAddress),
		ProofSetID:    req.ProofSetID,
		OperatorEmail: req.OperatorEmail,
		PublicURL:     *endpoint,
		Proof:         req.Proof,
	}); err != nil {
		if errors.Is(err, registrar.ErrDIDNotAllowed) {
			return c.String(http.StatusForbidden, "DID not allowed to register, contact Storacha team for help registering")
		}
		if errors.Is(err, registrar.ErrDIDAlreadyRegistered) {
			return c.String(http.StatusConflict, "DID already registered")
		}
		if errors.Is(err, registrar.ErrBadEndpoint) {
			return c.String(http.StatusBadRequest, "invalid PublicURL")
		}
		if errors.Is(err, registrar.ErrInvalidProof) {
			return c.String(http.StatusBadRequest, "invalid Proof")
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.NoContent(http.StatusCreated)
}

type RequestProofRequest struct {
	DID string `json:"did"`
}

type RequestProofResponse struct {
	Proof string `json:"proof"`
}

func (h *Handlers) RequestProof(c echo.Context) error {
	var req RequestProofRequest
	if err := c.Bind(&req); err != nil {
		return c.String(http.StatusBadRequest, "invalid request body")
	}

	operator, err := did.Parse(req.DID)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid DID")
	}

	resp, err := h.service.RequestProof(c.Request().Context(), operator)
	if err != nil {
		// TODO map the errors the service returns to http codes
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
	}

	proof, err := delegation.Format(resp)
	if err != nil {
		return c.String(http.StatusInternalServerError, "failed to read generated proof")
	}

	return c.JSON(http.StatusOK, RequestProofResponse{Proof: proof})
}

type IsRegisteredRequest struct {
	DID string `json:"did"`
}

func (h *Handlers) IsRegistered(c echo.Context) error {
	var req IsRegisteredRequest
	if err := c.Bind(&req); err != nil {
		return c.String(http.StatusBadRequest, "invalid request body")
	}

	operator, err := did.Parse(req.DID)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid DID")
	}

	registered, err := h.service.IsRegisteredDID(c.Request().Context(), operator)
	if err != nil {
		// TODO map the errors the service returns to http codes
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
	}

	if registered {
		return c.NoContent(http.StatusOK)
	}

	return c.NoContent(http.StatusNotFound)
}

type BenchmarkUploadRequest struct {
	OperatorDID      string `json:"operator_did"`
	OperatorEndpoint string `json:"operator_endpoint"`
	OperatorProof    string `json:"operator_proof"`
	Size             int64  `json:"size"`
}

type BenchmarkUploadResponse struct {
	AllocateDuration string `json:"allocate_duration"`
	UploadDuration   string `json:"upload_duration"`
	AcceptDuration   string `json:"accept_duration"`
	DownloadURL      string `json:"download_url,omitempty"`
	PieceLink        string `json:"piece_link,omitempty"`
}

func (h *Handlers) BenchmarkUpload(c echo.Context) error {
	var req BenchmarkUploadRequest
	if err := c.Bind(&req); err != nil {
		return c.String(http.StatusBadRequest, "invalid request body")
	}

	// validate request
	operator, err := did.Parse(req.OperatorDID)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid operator DID")
	}

	endpoint, err := url.Parse(req.OperatorEndpoint)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid operator endpoint URL")
	}

	if req.Size <= 0 {
		return c.String(http.StatusBadRequest, "size must be greater than 0")
	}

	result, err := h.benchmarkService.BenchmarkUpload(c.Request().Context(), benchmark.BenchmarkUploadParams{
		OperatorID:       operator,
		OperatorEndpoint: *endpoint,
		OperatorProof:    req.OperatorProof,
		Size:             req.Size,
	})
	if err != nil {
		// TODO map the errors the service returns to http codes
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, BenchmarkUploadResponse{
		AllocateDuration: result.AllocateDuration.String(),
		UploadDuration:   result.UploadDuration.String(),
		AcceptDuration:   result.AcceptDuration.String(),
		DownloadURL:      result.DownloadURL,
		PieceLink:        result.PieceLink,
	})
}

type BenchmarkDownloadRequest struct {
	Endpoint string `json:"endpoint"`
}

type BenchmarkDownloadResponse struct {
	DownloadDuration string `json:"download_duration"`
}

func (h *Handlers) BenchmarkDownload(c echo.Context) error {
	var req BenchmarkDownloadRequest
	if err := c.Bind(&req); err != nil {
		return c.String(http.StatusBadRequest, "invalid request body")
	}

	endpoint, err := url.Parse(req.Endpoint)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid endpoint URL")
	}

	result, err := h.benchmarkService.BenchmarkDownload(c.Request().Context(), *endpoint)
	if err != nil {
		// TODO map the errors the service returns to http codes
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, BenchmarkDownloadResponse{
		DownloadDuration: result.DownloadDuration.String(),
	})
}
