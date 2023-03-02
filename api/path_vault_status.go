package api

import (
	"context"
	"os"
	"strconv"

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

func checkIfNotEmpty(a string) bool {
	if a == "" {
		return false
	}
	return true
}

// pathPassphrase corresponds to POST gen/passphrase.
func (b *backend) pathGetUserVaultStatus(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// var err error
	backendLogger := b.logger

	// obtain details:
	identifier := d.Get("identifier").(string)
	signatureRSA := d.Get("signatureRSA").(string)

	// path where user data is stored
	path := config.StorageBasePath + identifier
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		logger.Log(backendLogger, config.Error, "getIdentifier: could not get storage entry", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	// Get User data
	var userData helpers.UserDetails
	err = entry.DecodeJSON(&userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "getIdentifier: could not get user details", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	dataToValidate := map[string]string{
		"identifier": identifier,
	}

	raVerificationState, remarks := helpers.VerifyJWTSignature(signatureRSA, dataToValidate, userData.UserRSAPublicKey, "RS256")

	if raVerificationState == false {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": remarks,
			},
		}, nil
	}

	waitPeriodStr := os.Getenv("WAIT_PERIOD")
	waitPeriod, _ := strconv.Atoi(waitPeriodStr)

	vaultStatus := &helpers.VaultStatus{
		Identifier:                 userData.Identifier,
		UserEmail:                  checkIfNotEmpty(userData.UserEmail),
		Guardians:                  []bool{checkIfNotEmpty(userData.Guardians[0]), checkIfNotEmpty(userData.Guardians[1]), checkIfNotEmpty(userData.Guardians[2])},
		UserMobile:                 checkIfNotEmpty(userData.UserMobile),
		UserRSAPublicKey:           checkIfNotEmpty(userData.UserRSAPublicKey),
		UserECDSAPublicKey:         checkIfNotEmpty(userData.UserECDSAPublicKey),
		SignedConsent:              checkIfNotEmpty(userData.SignedConsent),
		WalletThirdShard:           checkIfNotEmpty(userData.WalletThirdShard),
		LastRecoverySavedAt:        userData.LastRecoverySavedAt,
		IsRestoreInProgress:        userData.IsRestoreInProgress,
		RestoreInitiationTimestamp: userData.RestoreInitiationTimestamp,
		RestoreCompletionTimestamp: userData.RestoreInitiationTimestamp + int64(waitPeriod),
	}

	// return response
	return &logical.Response{
		Data: map[string]interface{}{
			"remarks": "success",
			"status":  true,
			"data":    vaultStatus,
		},
	}, nil
}
