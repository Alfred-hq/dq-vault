package api

import (
	"context"
	"fmt"
	"github.com/deqode/dq-vault/api/helpers"
	"github.com/deqode/dq-vault/config"
	"github.com/deqode/dq-vault/lib/adapter"
	"github.com/deqode/dq-vault/logger"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"net/http"
)

// pathPassphrase corresponds to POST gen/passphrase.
func (b *backend) pathStarkPublicKeysTyped(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	backendLogger := b.logger
	if err := helpers.ValidateFields(req, d); err != nil {
		logger.Log(backendLogger, config.Error, "signature:", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	uuid := d.Get("uuid").(string)
	_, seed, derivationPath, TypedData, _ := helpers.ParseTypedDataRequest(ctx, req, d, backendLogger)

	ethereumAdapter := adapter.NewEthereumAdapter(seed, derivationPath, false)

	//////
	//////// Generates and stores ECDSA private key in adapter
	_, err := ethereumAdapter.DerivePrivateKey(backendLogger)
	if err != nil {
		logger.Log(backendLogger, config.Error, "signature:", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	pubKey, err := ethereumAdapter.DerivePublicKey(backendLogger)
	if err != nil {
		logger.Log(backendLogger, config.Error, "address:", err.Error(), "which state", pubKey)
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	ethSignature, err := ethereumAdapter.CreateEip712SignedTransaction(TypedData, backendLogger)
	if err != nil {
		logger.Log(backendLogger, config.Error, "signature:", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}
	//////
	logger.Log(backendLogger, config.Info, "signature:", fmt.Sprintf("\n[INFO ] signature: created signature signature=[%v]", ethSignature))

	starknetAdapter := adapter.NewStarknetAdapter()
	_, err = starknetAdapter.DeriveStarkPrivateKey(ethSignature, backendLogger)
	xCoordinate, yCoordinate, _ := starknetAdapter.DeriveStarkPublicKeyPair(backendLogger)

	// return response
	return &logical.Response{
		Data: map[string]interface{}{
			"uuid":                          uuid,
			"stark_public_key":              xCoordinate,
			"stark_public_key_y_coordinate": yCoordinate,
		},
	}, nil
}
