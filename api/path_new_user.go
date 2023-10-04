package api

import (
	"context"
	"encoding/base64"

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
func (b *backend) pathNewUser(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// var err error
	backendLogger := b.logger

	// obtain user details:
	//userRSAPublicKey := d.Get("userRSAPublicKey").(string)
	userECDSAPublicKey := d.Get("userECDSAPublicKey").(string)
	identifier := d.Get("identifier").(string)
	//signatureRSA := d.Get("signatureRSA").(string)
	signatureECDSA := d.Get("signatureECDSA").(string)
	walletAddress := d.Get("walletAddress").(string)

	// store identifier at wallet public key(base64 encoded)
	base64EncodedECDSAPublicKey := base64.StdEncoding.EncodeToString([]byte(userECDSAPublicKey))
	storagePathIdentifier := config.StorageBasePath + base64EncodedECDSAPublicKey

	// create new user
	userData := &helpers.UserDetails{
		UserEmail:                        "",
		UnverifiedUserEmail:              "",
		Guardians:                        []string{"", "", ""},
		UnverifiedGuardians:              []string{"", "", ""},
		GuardiansAddLinkInitiation:       []int64{0, 0, 0},
		UserMobile:                       "",
		UnverifiedUserMobile:             "",
		UserRSAPublicKey:                 "",
		UserECDSAPublicKey:               userECDSAPublicKey,
		UnverifiedWalletThirdShard:       "",
		WalletThirdShard:                 "",
		LastRecoverySavedAt:              helpers.LastRecoverySaveLocation{GoogleDriveFileId: "", IcloudFileId: "", LocalFileId: ""},
		Identifier:                       identifier,
		IsRestoreInProgress:              false,
		EmailVerificationState:           false,
		MobileVerificationState:          false,
		PrimaryEmailVerificationOTP:      "xxxxxx",
		GuardianIdentifiers:              []string{"", "", ""},
		MobileVerificationOTP:            "xxxxxx",
		PrimaryEmailOTPGenerateTimestamp: int64(0),
		MobileOTPGenerateTimestamp:       int64(0),
		RestoreInitiationTimestamp:       int64(0),
		WalletIdentifierStoredAt:         base64EncodedECDSAPublicKey,
		SignedConsentForMnemonics:        "",
		SignedConsentForPrivateKey:       "",
		UserWalletAddress:                walletAddress,
		LastVetoedAt:                     int64(0),
	}

	dataToValidate := map[string]string{
		"identifier": identifier,
	}

	//rsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureRSA, dataToValidate, userRSAPublicKey, "RS256")
	//
	//if rsaVerificationState == false {
	//	return &logical.Response{
	//		Data: map[string]interface{}{
	//			"status":  false,
	//			"remarks": remarks,
	//		},
	//	}, nil
	//}

	ecdsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureECDSA, dataToValidate, userECDSAPublicKey, "ES256")

	if !ecdsaVerificationState {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": remarks,
			},
		}, nil
	}

	walletIdentifierDetails := &helpers.WalletIdentifierStorage{
		WalletIdentifier: identifier,
	}

	identifierStore, err := logical.StorageEntryJSON(storagePathIdentifier, walletIdentifierDetails)
	if err != nil {
		logger.Log(backendLogger, config.Error, "registerNewUser: could not create storage entry", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	if err = req.Storage.Put(ctx, identifierStore); err != nil {
		logger.Log(backendLogger, config.Error, "registerNewUser: could not put identifier info in storage", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// creates storage entry with user JSON encoded value
	storagePath := config.StorageBasePath + identifier
	store, err := logical.StorageEntryJSON(storagePath, userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "registerNewUser: could not create storage entry", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// put user information in store
	if err = req.Storage.Put(ctx, store); err != nil {
		logger.Log(backendLogger, config.Error, "registerNewUser: could not put user info in storage", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// return response
	return &logical.Response{
		Data: map[string]interface{}{
			"status":  true,
			"remarks": "successfully registered wallet!",
		},
	}, nil
}
