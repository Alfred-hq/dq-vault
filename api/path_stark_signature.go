package api

import (
	"context"
	"github.com/deqode/dq-vault/api/helpers"
	"github.com/deqode/dq-vault/config"
	"github.com/deqode/dq-vault/lib/adapter"
	"github.com/deqode/dq-vault/logger"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"net/http"
)

// pathPassphrase corresponds to POST gen/passphrase.
func (b *backend) pathStarkSignature(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	backendLogger := b.logger
	if err := helpers.ValidateFields(req, d); err != nil {
		logger.Log(backendLogger, config.Error, "signature:", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	uuid := d.Get("starkUUID").(string)
	payload := d.Get("payloadHash").(string)

	path := config.StarkStorageBasePath + uuid
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		logger.Log(backendLogger, config.Error, "signature:", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	var userInfo helpers.StarknetUser
	err = entry.DecodeJSON(&userInfo)
	if err != nil {
		logger.Log(backendLogger, config.Error, "signature:", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	starknetAdapter := adapter.NewStarknetAdapter()
	starknetAdapter.PrivateKey = userInfo.PrivateKey
	signature, _ := starknetAdapter.CreateSignature(payload, backendLogger)

	// return response
	return &logical.Response{
		Data: map[string]interface{}{
			"starkUUID": uuid,
			"signature": signature,
		},
	}, nil
}
