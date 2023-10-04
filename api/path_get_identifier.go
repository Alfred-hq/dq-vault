package api

import (
	"context"
	"encoding/base64"
	"os"
	"strconv"
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
func (b *backend) pathGetIdentifier(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// var err error
	backendLogger := b.logger

	// obtain details:
	userECDSAPublicKey := d.Get("userECDSAPublicKey").(string)
	signatureECDSA := d.Get("signatureECDSA").(string)

	base64EncodedECDSAPublicKey := base64.StdEncoding.EncodeToString([]byte(userECDSAPublicKey))

	// path where user data is stored
	path := config.StorageBasePath + base64EncodedECDSAPublicKey
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		logger.Log(backendLogger, config.Error, "getIdentifier: could not get storage entry", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	// Get User data
	var walletIdentifier helpers.WalletIdentifierStorage
	err = entry.DecodeJSON(&walletIdentifier)
	if err != nil {
		logger.Log(backendLogger, config.Error, "getIdentifier: could not get identifier details", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	dataToValidate := map[string]string{
		"userECDSAPublicKey": userECDSAPublicKey,
	}

	ecdsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureECDSA, dataToValidate, userECDSAPublicKey, "ES256")

	if ecdsaVerificationState == false {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": remarks,
			},
		}, nil
	}

	identifierPath := config.StorageBasePath + walletIdentifier.WalletIdentifier
	identifierEntry, err := req.Storage.Get(ctx, identifierPath)
	if err != nil {
		logger.Log(backendLogger, config.Error, "initiateWalletRestoration: could not get user data from storage", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	// Get User data
	var userData helpers.UserDetails
	err = identifierEntry.DecodeJSON(&userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "initiateWalletRestoration: unable to get user data", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	waitTimeAfterVetoStr := os.Getenv("WAIT_TIME_AFTER_VETO")

	waitTimeAfterVeto, err := strconv.Atoi(waitTimeAfterVetoStr)
	if err != nil {
		logger.Log(backendLogger, config.Error, "intiateWalletRestoration: could not convert number to string", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	currentTime := time.Now().Unix()

	if (currentTime - userData.LastVetoedAt) < int64(waitTimeAfterVeto) {
		return &logical.Response{
			Data: map[string]interface{}{
				"status": false,
				"remarks": map[string]interface{}{
					"message":                "Vault restoration locked",
					"restorationLockedUntil": userData.LastVetoedAt + int64(waitTimeAfterVeto),
					"vetoedBy":               userData.LastVetoedBy,
				},
			},
		}, nil
	}

	// return response
	return &logical.Response{
		Data: map[string]interface{}{
			"remarks": walletIdentifier.WalletIdentifier,
			"status":  true,
		},
	}, nil
}
