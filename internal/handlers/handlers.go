package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/labstack/echo/v4"
	"github.com/storacha/delegator/internal/services/benchmark"
	"github.com/storacha/delegator/internal/services/registrar"
	"github.com/storacha/go-ucanto/core/delegation"
	"github.com/storacha/go-ucanto/did"
	"github.com/storacha/go-ucanto/principal"
	"github.com/storacha/go-ucanto/principal/signer"
)

type Handlers struct {
	id               principal.Signer
	service          *registrar.Service
	benchmarkService *benchmark.Service
}

func NewHandlers(svcID principal.Signer, svc *registrar.Service, benchmarkSvc *benchmark.Service) *Handlers {
	return &Handlers{
		id:               svcID,
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

// DIDDocumentResponse is a did document that describes a did subject.
// See https://www.w3.org/TR/did-core/#dfn-did-documents.
type DIDDocumentResponse struct {
	Context            []string             `json:"@context"` // https://w3id.org/did/v1
	ID                 string               `json:"id"`
	Controller         []string             `json:"controller,omitempty"`
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
	Authentication     []string             `json:"authentication,omitempty"`
	AssertionMethod    []string             `json:"assertionMethod,omitempty"`
}

// VerificationMethod describes how to authenticate or authorize interactions
// with a did subject.
// See https://www.w3.org/TR/did-core/#dfn-verification-method.
type VerificationMethod struct {
	ID                 string `json:"id,omitempty"`
	Type               string `json:"type,omitempty"`
	Controller         string `json:"controller,omitempty"`
	PublicKeyMultibase string `json:"publicKeyMultibase,omitempty"`
}

func (h *Handlers) DIDDocument(c echo.Context) error {
	doc := DIDDocumentResponse{
		Context: []string{"https://w3id.org/did/v1"},
		ID:      h.id.DID().String(),
	}

	if s, ok := h.id.(signer.WrappedSigner); ok {
		vid := fmt.Sprintf("%s#owner", s.DID())
		doc.VerificationMethod = []VerificationMethod{
			{
				ID:                 vid,
				Type:               "Ed25519VerificationKey2020",
				Controller:         s.DID().String(),
				PublicKeyMultibase: strings.TrimPrefix(s.Unwrap().DID().String(), "did:key:"),
			},
		}
		doc.Authentication = []string{vid}
		doc.AssertionMethod = []string{vid}
	}

	return c.JSON(http.StatusOK, doc)
}

type RegisterRequest struct {
	Operator      string `json:"operator"`
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
	operator, err := did.Parse(req.Operator)
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
		var status int
		var message string
		if errors.Is(err, registrar.ErrContractProviderNotRegistered) {
			status = http.StatusUnprocessableEntity
			message = "Provider not registered with smart-contract, must register first"
		} else if errors.Is(err, registrar.ErrDIDNotAllowed) {
			status = http.StatusForbidden
			message = "DID not allowed to register, contact Storacha team for help registering"
		} else if errors.Is(err, registrar.ErrDIDAlreadyRegistered) {
			status = http.StatusConflict
			message = "DID already registered"
		} else if errors.Is(err, registrar.ErrBadEndpoint) {
			status = http.StatusBadRequest
			message = "invalid PublicURL"
		} else if errors.Is(err, registrar.ErrInvalidProof) {
			status = http.StatusBadRequest
			message = "invalid Proof"
		} else {
			status = http.StatusInternalServerError
			message = err.Error()
		}
		log.Error("failed to register", "operator", operator, "error", err)
		return c.JSON(status, map[string]string{
			"error": message,
		})
	}

	return c.NoContent(http.StatusCreated)
}

func (h *Handlers) RequestProof(c echo.Context) error {
	return c.String(http.StatusGone, "this endpoint is deprecated, use /registrar/request-proofs instead")
}

type RequestProofsRequest struct {
	DID string `json:"did"`
}

type RequestProofsResponse struct {
	Proofs Proofs `json:"proofs"`
}

type Proofs struct {
	Indexer       string `json:"indexer"`
	EgressTracker string `json:"egress_tracker"`
}

func (h *Handlers) RequestProofs(c echo.Context) error {
	var req RequestProofsRequest
	if err := c.Bind(&req); err != nil {
		return c.String(http.StatusBadRequest, "invalid request body")
	}

	operator, err := did.Parse(req.DID)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid DID")
	}

	indexerProof, egressTrackerProof, err := h.service.RequestProofs(c.Request().Context(), operator)
	if err != nil {
		// Map service errors to appropriate HTTP status codes
		status := http.StatusInternalServerError
		if errors.Is(err, registrar.ErrDIDNotAllowed) || errors.Is(err, registrar.ErrDIDNotRegistered) {
			status = http.StatusForbidden
		}

		return c.JSON(status, map[string]string{
			"error": err.Error(),
		})
	}

	indexerProofStr, err := delegation.Format(indexerProof)
	if err != nil {
		return c.String(http.StatusInternalServerError, "failed to read generated indexer proof")
	}

	egressTrackerProofStr, err := delegation.Format(egressTrackerProof)
	if err != nil {
		return c.String(http.StatusInternalServerError, "failed to read generated egress tracker proof")
	}

	return c.JSON(http.StatusOK, RequestProofsResponse{Proofs: Proofs{
		Indexer:       indexerProofStr,
		EgressTracker: egressTrackerProofStr,
	}})
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
	DownloadURL      string `json:"download_url"`
	PieceLink        string `json:"piece_link"`
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

// ContractApprovalRequest represents a request to approve a provider for registration
// before full registration with the Storacha network.
type ContractApprovalRequest struct {
	// DID is the decentralized identifier of the operator requesting approval
	Operator string `json:"operator"`
	// OwnerAddress is the Ethereum address of the provider owner (hex format)
	OwnerAddress string `json:"owner_address"`
	// Signature is the cryptographic signature proving ownership/authorization
	Signature []byte `json:"signature"`
}

// RequestContractApproval handles HTTP requests for contract approval. It validates
// the operator's DID, owner address, and signature, then processes the approval request
// through the registrar service. The provider must already be registered with the
// smart contract and be on the allow list before approval can be granted.
//
// Returns:
//   - 204 No Content on success
//   - 400 Bad Request for invalid input (DID, owner address, signature, or public URL)
//   - 403 Forbidden if the DID is not on the allow list
//   - 422 Unprocessable Entity if the provider is not registered with the smart contract
//   - 500 Internal Server Error for unexpected errors
func (h *Handlers) RequestContractApproval(c echo.Context) error {
	var req ContractApprovalRequest
	if err := c.Bind(&req); err != nil {
		return c.String(http.StatusBadRequest, "invalid request body")
	}

	// parse and validate request
	operator, err := did.Parse(req.Operator)
	if err != nil {
		return c.String(http.StatusBadRequest, "invalid DID")
	}
	if !common.IsHexAddress(req.OwnerAddress) {
		return c.String(http.StatusBadRequest, "invalid OwnerAddress")
	}
	if len(req.Signature) == 0 {
		return c.String(http.StatusBadRequest, "invalid signature")
	}
	if err := h.service.RequestContractApproval(c.Request().Context(), registrar.RequestApprovalParams{
		Operator:     operator,
		OwnerAddress: common.HexToAddress(req.OwnerAddress),
		Signature:    req.Signature,
	}); err != nil {
		if errors.Is(err, registrar.ErrContractProviderNotRegistered) {
			return c.String(http.StatusUnprocessableEntity, "Provider not registered with smart-contract, must register first")
		}
		if errors.Is(err, registrar.ErrDIDNotAllowed) {
			return c.String(http.StatusForbidden, "DID not allowed to register, contact Storacha team for help registering")
		}
		if errors.Is(err, registrar.ErrInvalidDID) {
			return c.String(http.StatusBadRequest, "invalid DID")
		}
		if errors.Is(err, registrar.ErrInvalidSignature) {
			return c.String(http.StatusBadRequest, "signature is invalid")
		}
		log.Error("failed to request contract approval", "error", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.NoContent(http.StatusNoContent)
}
