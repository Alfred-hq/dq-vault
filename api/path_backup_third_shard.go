package api

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryadavDeqode/dq-vault/api/helpers"
	"github.com/ryadavDeqode/dq-vault/config"
	"github.com/ryadavDeqode/dq-vault/logger"
	"net/http"
)

// pathPassphrase corresponds to POST gen/passphrase.
func (b *backend) pathBackupThirdShard(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// var err error
	backendLogger := b.logger

	// obtain details:
	identifier := d.Get("identifier").(string)
	walletThirdShard := d.Get("walletThirdShard").(string)
	rsaEncryptedMnemonicEncryptionAESKey := d.Get("rsaEncryptedMnemonicEncryptionAESKey").(string)
	userRSAPublicKey := d.Get("userRSAPublicKey").(string)
	signatureRSA := d.Get("signatureRSA").(string)
	signatureECDSA := d.Get("signatureECDSA").(string)

	// path where user data is stored
	path := config.StorageBasePath + identifier
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		logger.Log(backendLogger, config.Error, "addThirdShard: could not fetch data from storage", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	// Get User data
	var userData helpers.UserDetails
	err = entry.DecodeJSON(&userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "addThirdShard: could not encode JSON", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	dataToValidate := map[string]string{
		"identifier":       identifier,
		"walletThirdShard": walletThirdShard,
	}

	rsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureRSA, dataToValidate, userRSAPublicKey, "RS256")

	if rsaVerificationState == false {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": remarks,
			},
		}, nil
	}

	ecdsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureECDSA, dataToValidate, userData.UserECDSAPublicKey, "ES256")

	if ecdsaVerificationState == false {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": remarks,
			},
		}, nil
	}

	userData.WalletThirdShard = walletThirdShard
	userData.RsaEncryptedMnemonicEncryptionAESKey = rsaEncryptedMnemonicEncryptionAESKey
	userData.UserRSAPublicKey = userRSAPublicKey
	userData.LastRecoverySavedAt.GoogleDriveFileId = ""
	userData.LastRecoverySavedAt.IcloudFileId = ""
	userData.LastRecoverySavedAt.LocalFileId = ""

	store, err := logical.StorageEntryJSON(path, userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "addThirdShard: could not get storage entry", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// put user information in store
	if err = req.Storage.Put(ctx, store); err != nil {
		logger.Log(backendLogger, config.Error, "addThirdShard: could not put user information in store", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// return response
	return &logical.Response{
		Data: map[string]interface{}{
			"status":  true,
			"remarks": "success!",
		},
	}, nil
}
