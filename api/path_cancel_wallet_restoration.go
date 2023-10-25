package api

import (
	"context"
	// "errors"
	// "fmt"

	// "encoding/json"
	// "fmt"
	"net/http"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/alfred-hq/dq-vault/api/helpers"
	"github.com/alfred-hq/dq-vault/config"
	"github.com/alfred-hq/dq-vault/logger"
)

// pathPassphrase corresponds to POST gen/passphrase.
func (b *backend) pathCancelWalletRestoration(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// var err error
	backendLogger := b.logger

	// obtain details:
	identifier, _ := d.Get("identifier").(string)
	signatureRSA, _ := d.Get("signatureRSA").(string)

	// path where user data is stored
	path := config.StorageBasePath + identifier
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		logger.Log(backendLogger, config.Error, "cancelWalletRestoration: could not get storage entry", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	// Get User data
	var userData helpers.UserDetails
	err = entry.DecodeJSON(&userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "cancelWalletRestoration: could not get user data", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	dataToValidate := map[string]string{
		"identifier": identifier,
	}

	rsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureRSA, dataToValidate, userData.UserRSAPublicKey, "RS256")

	if rsaVerificationState == false {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": remarks,
			},
		}, nil
	}

	userData.IsRestoreInProgress = false
	userData.RestoreInitiationTimestamp = int64(0)
	store, err := logical.StorageEntryJSON(path, userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "cancelWalletRestoration: could not get storage entry", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// put user information in store
	if err = req.Storage.Put(ctx, store); err != nil {
		logger.Log(backendLogger, config.Error, "cancelWalletRestoration: could not store user data", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// return response
	return &logical.Response{
		Data: map[string]interface{}{
			"status":  true,
			"remarks": "wallet restoration cancelled",
		},
	}, nil
}
