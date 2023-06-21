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

func (b *backend) pathRegisterStarknetUser(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var err error
	backendLogger := b.logger
	if err = helpers.ValidateFields(req, d); err != nil {
		logger.Log(backendLogger, config.Error, "register:", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	ethSignature := d.Get("ethSignature").(string)
	address := d.Get("address").(string)

	// generate new random UUID
	uuid := helpers.NewUUID()
	for helpers.StarkUUIDExists(ctx, req, uuid) {
		uuid = helpers.NewUUID()
	}

	// generated storage path to store user info
	storagePath := config.StarkStorageBasePath + uuid

	starknetAdapter := adapter.NewStarknetAdapter()
	privateKey, err := starknetAdapter.DeriveStarkPrivateKey(ethSignature, backendLogger)
	if err != nil {
		logger.Log(backendLogger, config.Error, "signature:", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	// create object to store user information
	user := &helpers.StarknetUser{
		UUID:       uuid,
		Address:    address,
		PrivateKey: privateKey,
	}

	// creates strorage entry with user JSON encoded value
	store, err := logical.StorageEntryJSON(storagePath, user)
	if err != nil {
		logger.Log(backendLogger, config.Error, "register:", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// put user information in store
	if err = req.Storage.Put(ctx, store); err != nil {
		logger.Log(backendLogger, config.Error, "register:", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	xCoordinate, yCoordinate, _ := starknetAdapter.DeriveStarkPublicKeyPair(backendLogger)

	// return response
	return &logical.Response{
		Data: map[string]interface{}{
			"starkUUID":                     uuid,
			"stark_public_key":              xCoordinate,
			"stark_public_key_y_coordinate": yCoordinate,
		},
	}, nil
}
