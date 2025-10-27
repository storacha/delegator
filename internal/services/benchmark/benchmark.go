package benchmark

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ipfs/go-cid"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	"github.com/storacha/delegator/internal/services/benchmark/client"
	"github.com/storacha/go-libstoracha/capabilities/blob"
	"github.com/storacha/go-libstoracha/capabilities/blob/replica"
	"github.com/storacha/go-libstoracha/capabilities/pdp"
	"github.com/storacha/go-ucanto/core/delegation"
	"github.com/storacha/go-ucanto/core/ipld/hash/sha256"
	"github.com/storacha/go-ucanto/did"
	"github.com/storacha/go-ucanto/principal"
	"go.uber.org/fx"
)

type Service struct {
	signer principal.Signer
}

type ServiceParams struct {
	fx.In

	// the identity of the benchmarker service
	Signer principal.Signer
}

func New(params ServiceParams) *Service {
	return &Service{signer: params.Signer}
}

type BenchmarkUploadParams struct {
	// The DID of the operator requesting benchmark
	OperatorID did.DID
	// The domain of the operator requesting benchmark
	OperatorEndpoint url.URL
	// The proof from the operator allowing the Service to perform a benchmark
	OperatorProof string
	// The size of the data to test benchmarking with
	Size int64
}

type BenchmarkUploadResult struct {
	AllocateDuration time.Duration
	UploadDuration   time.Duration
	AcceptDuration   time.Duration
	DownloadURL      string
	PieceLink        string
}

func (s *Service) BenchmarkUpload(ctx context.Context, params BenchmarkUploadParams) (*BenchmarkUploadResult, error) {
	proof, err := s.assertAndParseBenchmarkProofValid(params.OperatorProof, params.OperatorID)
	if err != nil {
		// TODO returned typed error for handler assertion
		// should be bad request in api
		return nil, fmt.Errorf("operator proof invalid for storage benchmark: %w", err)
	}

	c, err := client.NewClient(client.Config{
		ID:             s.signer,
		StorageNodeID:  params.OperatorID,
		StorageNodeURL: params.OperatorEndpoint,
		StorageProof:   delegation.FromDelegation(proof),
	})
	if err != nil {
		// TODO should be an internal error in api
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	payload, err := generateBenchmarkPayload(params.Size)
	if err != nil {
		return nil, fmt.Errorf("failed to generate benchmark payload: %w", err)
	}
	payloadDigest, err := sha256.Hasher.Sum(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to hash benchmark payload: %w", err)
	}
	allocateStartTime := time.Now()
	address, err := c.BlobAllocate(
		ctx,
		params.OperatorID,
		payloadDigest.Bytes(),
		uint64(len(payload)),
		cidlink.Link{Cid: cid.NewCidV1(cid.Raw, payloadDigest.Bytes())},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate benchmark payload: %w", err)
	}
	allocateDuration := time.Since(allocateStartTime)

	uploadReq, err := http.NewRequestWithContext(ctx, http.MethodPut, address.URL.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create storage benchmark request to operator node: %w", err)
	}
	uploadReq.Header = address.Headers
	uploadReq.ContentLength = int64(len(payload)) // Set content length for proper progress tracking

	uploadStartTime := time.Now()
	uploadRes, err := http.DefaultClient.Do(uploadReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send storage benchmark request to operator node %s: %w", address.URL.String(), err)
	}
	uploadDuration := time.Since(uploadStartTime)
	defer uploadRes.Body.Close()

	if uploadRes.StatusCode >= 300 || uploadRes.StatusCode < 200 {
		resData, err := io.ReadAll(uploadRes.Body)
		if err != nil {
			return nil, fmt.Errorf("unsuccessful put, status: %s", uploadRes.Status)
		}
		return nil, fmt.Errorf("failed put operation to operator node, status: %s, body: %s", uploadRes.Status, string(resData))
	}

	acceptStartTime := time.Now()
	blobResult, err := c.BlobAccept(
		ctx,
		params.OperatorID,
		payloadDigest.Bytes(),
		uint64(len(payload)),
		cidlink.Link{Cid: cid.NewCidV1(cid.Raw, payloadDigest.Bytes())},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to accept benchmark payload: %w", err)
	}
	acceptDuration := time.Since(acceptStartTime)

	var downloadURL string
	if len(blobResult.LocationCommitment.Location) > 0 {
		downloadURL = blobResult.LocationCommitment.Location[0].String()
	}

	var pieceLink string
	if blobResult.PDPAccept != nil {
		pieceLink = blobResult.PDPAccept.Piece.V1Link().String()
	}

	return &BenchmarkUploadResult{
		AllocateDuration: allocateDuration,
		UploadDuration:   uploadDuration,
		AcceptDuration:   acceptDuration,
		DownloadURL:      downloadURL,
		PieceLink:        pieceLink,
	}, nil
}

type BenchmarkDownloadResult struct {
	DownloadDuration time.Duration
}

func (s *Service) BenchmarkDownload(ctx context.Context, endpoint url.URL) (*BenchmarkDownloadResult, error) {
	downloadReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create benchmark download request to operator node %s: %w", endpoint.String(), err)
	}
	downloadStartTime := time.Now()
	downloadRes, err := http.DefaultClient.Do(downloadReq)
	if err != nil {
		return nil, fmt.Errorf("failed to do request for download from %s for benchmark: %w", endpoint.String(), err)
	}
	defer downloadRes.Body.Close()
	// we don't care about the data, but we need to read it all to simulate a full download
	_, err = io.Copy(io.Discard, downloadRes.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to download body for benchmark download from %s for benchmark: %w", endpoint.String(), err)
	}
	downloadDuration := time.Since(downloadStartTime)

	return &BenchmarkDownloadResult{downloadDuration}, nil
}

func (s *Service) assertAndParseBenchmarkProofValid(proof string, operator did.DID) (delegation.Delegation, error) {
	if strings.TrimSpace(proof) == "" {
		return nil, fmt.Errorf("proof cannot be empty")
	}

	strgDelegation, err := delegation.Parse(proof)
	if err != nil {
		return nil, err
	}

	expiration := strgDelegation.Expiration()

	now := time.Now().Unix()
	if expiration != nil {
		if *expiration != 0 && *expiration <= int(now) {
			return nil, fmt.Errorf("delegation expired. expiration: %d, now: %d", expiration, now)
		}
	}
	if strgDelegation.Issuer().DID().String() != operator.DID().String() {
		return nil, fmt.Errorf("delegation issuer (%s) does not match provider DID (%s)", strgDelegation.Issuer().DID().String(), operator.DID().String())
	}
	// For test storage, the audience should be the delegator service (not upload service)
	if strgDelegation.Audience().DID().String() != s.signer.DID().String() {
		return nil, fmt.Errorf("delegation audience (%s) does not match delegator service DID (%s)", strgDelegation.Audience().DID().String(), s.signer.DID().String())
	}
	var expectedCapabilities = map[string]struct{}{
		blob.AcceptAbility:      {},
		blob.AllocateAbility:    {},
		replica.AllocateAbility: {},
		pdp.InfoAbility:         {},
	}
	if len(strgDelegation.Capabilities()) != len(expectedCapabilities) {
		return nil, fmt.Errorf("expected exact %v capabilities, got %v", expectedCapabilities, strgDelegation.Capabilities())
	}
	for _, c := range strgDelegation.Capabilities() {
		_, ok := expectedCapabilities[c.Can()]
		if !ok {
			return nil, fmt.Errorf("unexpected capability: %s", c.Can())
		}
		if c.With() != operator.DID().String() {
			return nil, fmt.Errorf("capability %s has unexpected resource %s, expected: %s", c.Can(), c.With(), operator.DID().String())
		}
	}

	return strgDelegation, nil
}

func generateBenchmarkPayload(size int64) ([]byte, error) {
	if size < 0 {
		return nil, fmt.Errorf("size must be non-negative, got: %d", size)
	}

	payload := make([]byte, size)
	_, err := rand.Read(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random data: %w", err)
	}

	return payload, nil
}
