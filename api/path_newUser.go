package api

import (
	"context"
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
func (b *backend) pathNewUser(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// var err error
	backendLogger := b.logger

	// obtain user details:
	userRSAPublicKey := d.Get("userRSAPublicKey").(string)     // base64 encoded pem key
	userECDSAPublicKey := d.Get("userECDSAPublicKey").(string) // hex
	identifier := d.Get("identifier").(string)                 // uuid
	signatureRSA := d.Get("signatureRSA").(string)             // JWT token
	signatureECDSA := d.Get("signatureECDSA").(string)

	// create new user
	userData := &helpers.UserDetails{
		UserEmail:                          "",
		UnverifiedUserEmail:                "",
		GuardianEmail1:                     "",
		UnverifiedGuardianEmail1:           "",
		GuardianEmail2:                     "",
		UnverifiedGuardianEmail2:           "",
		GuardianEmail3:                     "",
		UnverifiedGuardianEmail3:           "",
		UserMobile:                         "",
		UnverifiedUserMobile:               "",
		UserRSAPublicKey:                   userRSAPublicKey,
		UserECDSAPublicKey:                 userECDSAPublicKey,
		WalletThirdShard:                   "",
		Identifier:                         identifier,
		IsRestoreInProgress:                false,
		EmailVerificationState:             false,
		MobileVerificationState:            false,
		PrimaryEmailVerificationOTP:        "xxxxxx",
		GuardianEmail1VerificationOTP:      "xxxxxx",
		GuardianEmail2VerificationOTP:      "xxxxxx",
		GuardianEmail3VerificationOTP:      "xxxxxx",
		MobileVerificationOTP:              "xxxxxx",
		PrimaryEmailOTPGenerateTimestamp:   int64(0),
		GuardianEmail1OTPGenerateTimestamp: int64(0),
		GuardianEmail2OTPGenerateTimestamp: int64(0),
		GuardianEmail3OTPGenerateTimestamp: int64(0),
		MobileOTPGenerateTimestamp:         int64(0),
		RestoreInitiationTimestamp:         int64(0),
	}

	dataToValidate := map[string]string{
		"identifier": identifier,
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

	ecdsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureECDSA, dataToValidate, userECDSAPublicKey, "ES256")

	if ecdsaVerificationState == false {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": remarks,
			},
		}, nil
	}

	// creates strorage entry with user JSON encoded value
	storagePath := config.StorageBasePath + identifier
	store, err := logical.StorageEntryJSON(storagePath, userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "registerNewUser:", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// put user information in store
	if err = req.Storage.Put(ctx, store); err != nil {
		logger.Log(backendLogger, config.Error, "registerNewUser:", err.Error())
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
