package providers

import (
	"context"
	crypto_ed25519 "crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/storacha/delegator/internal/services/registrar"
	"github.com/storacha/forgectl/pkg/services/chain"
	"github.com/storacha/forgectl/pkg/services/inspector"
	"github.com/storacha/forgectl/pkg/services/operator"
	"github.com/storacha/forgectl/pkg/services/types"
	"github.com/storacha/go-ucanto/core/delegation"
	"github.com/storacha/go-ucanto/did"
	"github.com/storacha/go-ucanto/principal"
	ed25519 "github.com/storacha/go-ucanto/principal/ed25519/signer"
	"github.com/storacha/go-ucanto/principal/signer"
	"go.uber.org/fx"

	"github.com/storacha/delegator/internal/config"
)

type SignerParams struct {
	fx.In
	Config *config.Config
}

type SignerResult struct {
	fx.Out
	Signer principal.Signer
}

func ProvideSigner(params SignerParams) (SignerResult, error) {
	var s principal.Signer
	var err error
	switch {
	case params.Config.Delegator.Key != "":
		s, err = ed25519.Parse(params.Config.Delegator.Key)
		if err != nil {
			return SignerResult{}, fmt.Errorf("failed to parse multibase key: %w", err)
		}
	case params.Config.Delegator.KeyFile != "":
		s, err = signerFromEd25519PEMFile(params.Config.Delegator.KeyFile)
		if err != nil {
			return SignerResult{}, fmt.Errorf("failed to parse key file: %w", err)
		}
	default:
		return SignerResult{}, fmt.Errorf("no key or key file provided")
	}

	did, err := did.Parse(params.Config.Delegator.DID)
	if err != nil {
		return SignerResult{}, fmt.Errorf("failed to parse did: %w", err)
	}

	signer, err := signer.Wrap(s, did)
	if err != nil {
		return SignerResult{}, err
	}

	return SignerResult{Signer: signer}, nil
}

func signerFromEd25519PEMFile(path string) (principal.Signer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pemData, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}

	var privateKey *crypto_ed25519.PrivateKey
	rest := pemData

	// Loop until no more blocks
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			// No more PEM blocks
			break
		}
		rest = remaining

		// Look for "PRIVATE KEY"
		if block.Type == "PRIVATE KEY" {
			parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
			}

			// We expect a ed25519 private key, cast it
			key, ok := parsedKey.(crypto_ed25519.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("the parsed key is not an ED25519 private key")
			}
			privateKey = &key
			break
		}
	}

	if privateKey == nil {
		return nil, fmt.Errorf("could not find a PRIVATE KEY block in the PEM file")
	}
	return ed25519.FromRaw(*privateKey)
}

type IndexingServiceWebDIDParams struct {
	fx.In
	Config *config.Config
}

type IndexingServiceWebDIDResult struct {
	fx.Out
	IndexingServiceWebDID did.DID `name:"indexing_service_web_did"`
}

func ProvideIndexingServiceWebDID(params IndexingServiceWebDIDParams) (IndexingServiceWebDIDResult, error) {
	parsedDID, err := did.Parse(params.Config.Delegator.IndexingServiceWebDID)
	if err != nil {
		return IndexingServiceWebDIDResult{}, fmt.Errorf("failed to parse indexing service DID: %w", err)
	}

	return IndexingServiceWebDIDResult{IndexingServiceWebDID: parsedDID}, nil
}

type UploadServiceDIDParams struct {
	fx.In
	Config *config.Config
}

type UploadServiceDIDResult struct {
	fx.Out
	UploadServiceDID did.DID `name:"upload_service_did"`
}

func ProvideUploadServiceDID(params UploadServiceDIDParams) (UploadServiceDIDResult, error) {
	parsedDID, err := did.Parse(params.Config.Delegator.UploadServiceDID)
	if err != nil {
		return UploadServiceDIDResult{}, fmt.Errorf("failed to parse upload service DID: %w", err)
	}

	return UploadServiceDIDResult{UploadServiceDID: parsedDID}, nil
}

type IndexingServiceProofParams struct {
	fx.In
	Config *config.Config
}

type IndexingServiceProofResult struct {
	fx.Out
	IndexingServiceProof delegation.Delegation `name:"indexing_service_proof"`
}

func ProvideIndexingServiceProof(params IndexingServiceProofParams) (IndexingServiceProofResult, error) {
	proof, err := delegation.Parse(params.Config.Delegator.IndexingServiceProof)
	if err != nil {
		return IndexingServiceProofResult{}, fmt.Errorf("failed to parse indexing service proof: %w", err)
	}

	return IndexingServiceProofResult{IndexingServiceProof: proof}, nil
}

type EgressTrackingServiceDIDParams struct {
	fx.In
	Config *config.Config
}

type EgressTrackingServiceDIDResult struct {
	fx.Out
	EgressTrackingServiceDID did.DID `name:"egress_tracking_service_did"`
}

func ProvideEgressTrackingServiceDID(params EgressTrackingServiceDIDParams) (EgressTrackingServiceDIDResult, error) {
	parsedDID, err := did.Parse(params.Config.Delegator.EgressTrackingServiceDID)
	if err != nil {
		return EgressTrackingServiceDIDResult{}, fmt.Errorf("failed to parse egress tracking service DID: %w", err)
	}

	return EgressTrackingServiceDIDResult{EgressTrackingServiceDID: parsedDID}, nil
}

type EgressTrackingServiceProofParams struct {
	fx.In
	Config *config.Config
}

type EgressTrackingServiceProofResult struct {
	fx.Out
	EgressTrackingServiceProof delegation.Delegation `name:"egress_tracking_service_proof"`
}

func ProvideEgressTrackingServiceProof(params EgressTrackingServiceProofParams) (EgressTrackingServiceProofResult, error) {
	proof, err := delegation.Parse(params.Config.Delegator.EgressTrackingServiceProof)
	if err != nil {
		return EgressTrackingServiceProofResult{}, fmt.Errorf("failed to parse egress tracking service proof: %w", err)
	}
	return EgressTrackingServiceProofResult{EgressTrackingServiceProof: proof}, nil
}

type SmartContractOperator struct {
	o *operator.Service
}

func (s *SmartContractOperator) IsRegisteredProvider(ctx context.Context, provider common.Address) (bool, error) {
	return s.o.RegistryContract.IsRegisteredProvider(&bind.CallOpts{Context: ctx}, provider)
}

func (s *SmartContractOperator) GetProviderByAddress(ctx context.Context, provider common.Address) (*types.ProviderInfo, error) {
	return s.o.GetProviderByAddress(ctx, provider)
}

func (s *SmartContractOperator) ApproveProvider(ctx context.Context, id uint64) (*types.ApprovalResult, error) {
	return s.o.ApproveProvider(ctx, id)
}

func ProvideContractOperator(cfg config.ContractOperatorConfig) (registrar.ContractOperator, error) {
	in, err := inspector.New(inspector.Config{
		ClientEndpoint:          cfg.ChainClientEndpoint,
		PaymentsContractAddress: common.HexToAddress(cfg.PaymentsContractAddress),
		ServiceContractAddress:  common.HexToAddress(cfg.ServiceContractAddress),
		ProviderRegistryAddress: common.HexToAddress(cfg.RegistryContractAddress),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize contract inspector: %w", err)
	}
	txtr, err := chain.NewTransactor(big.NewInt(cfg.Transactor.ChainID), chain.TransactorConfig{
		KeystorePath:     cfg.Transactor.KeystorePath,
		KeystorePassword: cfg.Transactor.KeystorePassword,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize contract transactor: %w", err)
	}

	op, err := operator.New(in, txtr)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize contract operator: %w", err)
	}

	return &SmartContractOperator{o: op}, nil
}
