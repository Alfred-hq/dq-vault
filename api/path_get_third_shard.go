package api

import (
	"context"
	"time"

	// "errors"
	// "fmt"

	// "encoding/json"
	// "fmt"
	"net/http"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryadavDeqode/dq-vault/api/helpers"
	"github.com/ryadavDeqode/dq-vault/config"
	"github.com/ryadavDeqode/dq-vault/logger"
)

// pathPassphrase corresponds to POST gen/passphrase.
func (b *backend) pathGetThirdShard(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// var err error
	backendLogger := b.logger

	// obtain details:
	identifier := d.Get("identifier").(string)
	signatureRSA := d.Get("signatureRSA").(string)

	// path where user data is stored
	path := config.StorageBasePath + identifier
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		logger.Log(backendLogger, config.Error, "getThirdShard:", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	// Get User data
	var userData helpers.UserDetails
	err = entry.DecodeJSON(&userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "getThirdShard:", err.Error())
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

	if userData.IsRestoreInProgress == false {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": "restoration is not started or vetoed by guardian", // who vetoed? when vetoed
			},
		}, nil
	}

	currentUnixTime := time.Now().Unix()
	if currentUnixTime-userData.RestoreInitiationTimestamp < 300 { // 24 hrs and env
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": "wait period not over, please wait", // at what time ?
			},
		}, nil
	}

	userData.IsRestoreInProgress = false
	userData.RestoreInitiationTimestamp = int64(0)

	store, err := logical.StorageEntryJSON(path, userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "getThirdShard:", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// put user information in store
	if err = req.Storage.Put(ctx, store); err != nil {
		logger.Log(backendLogger, config.Error, "getThirdShard:", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// return response
	return &logical.Response{
		Data: map[string]interface{}{
			"remarks": userData.WalletThirdShard,
			"status":  true,
		},
	}, nil
}
