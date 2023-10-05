package api

import (
	"context"
	// "errors"
	// "fmt"

	// "encoding/json"
	// "fmt"
	"net/http"

	"github.com/alfred-hq/dq-vault/api/helpers"
	"github.com/alfred-hq/dq-vault/config"
	"github.com/alfred-hq/dq-vault/logger"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
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
		logger.Log(backendLogger, config.Error, "getThirdShard: could not get storage entry", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	// Get User data
	var userData helpers.UserDetails
	err = entry.DecodeJSON(&userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "getThirdShard: could not get user details", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	dataToValidate := map[string]string{
		"identifier": identifier,
	}

	rsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureRSA, dataToValidate, userData.UserRSAPublicKey, "RS256")

	if !rsaVerificationState {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": remarks,
			},
		}, nil
	}

	//waitPeriodStr := os.Getenv("WAIT_PERIOD")
	//waitPeriod, _ := strconv.Atoi(waitPeriodStr)
	//currentUnixTime := time.Now().Unix()
	//if currentUnixTime-userData.RestoreInitiationTimestamp < int64(waitPeriod) {
	//	waitUntil := time.Unix(userData.RestoreInitiationTimestamp+int64(waitPeriod), 0).Format(time.RFC3339)
	//	return &logical.Response{
	//		Data: map[string]interface{}{
	//			"status":  false,
	//			"remarks": "wait period not over, wait till " + waitUntil,
	//		},
	//	}, nil
	//}

	//userData.IsRestoreInProgress = false
	//userData.RestoreInitiationTimestamp = int64(0)

	store, err := logical.StorageEntryJSON(path, userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "getThirdShard: could not set storage entry", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// put user information in store
	if err = req.Storage.Put(ctx, store); err != nil {
		logger.Log(backendLogger, config.Error, "getThirdShard: could not put user info in storage", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	recoveryDetails := &helpers.RecoveryDetails{
		ThirdShard:                           userData.WalletThirdShard,
		RsaEncryptedMnemonicEncryptionAESKey: userData.RsaEncryptedMnemonicEncryptionAESKey,
	}

	// return response
	return &logical.Response{
		Data: map[string]interface{}{
			"remarks": recoveryDetails,
			"status":  true,
		},
	}, nil
}
