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
	signatureECDSA := d.Get("signatureECDSA").(string)

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

	ecdsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureECDSA, dataToValidate, userData.UserECDSAPublicKey, "ES256")

	if !ecdsaVerificationState{
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
		UserEmail:                  userData.UserEmail,
		Guardians:                  []helpers.GuardianEmails{{checkIfNotEmpty(userData.Guardians[0]), userData.UnverifiedGuardians[0]}, {checkIfNotEmpty(userData.Guardians[1]), userData.UnverifiedGuardians[1]}, {checkIfNotEmpty(userData.Guardians[2]), userData.UnverifiedGuardians[2]}},
		UserMobile:                 userData.UserMobile,
		UserRSAPublicKey:           checkIfNotEmpty(userData.UserRSAPublicKey),
		UserECDSAPublicKey:         checkIfNotEmpty(userData.UserECDSAPublicKey),
		SignedConsentForMnemonics:  checkIfNotEmpty(userData.SignedConsentForMnemonics),
		SignedConsentForPrivateKey: checkIfNotEmpty(userData.SignedConsentForPrivateKey),
		LastVetoedBy:               userData.LastVetoedBy,
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
