package api

import (
	"context"
	"errors"
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
	userRSAPublicKey := d.Get("userRSAPublicKey").(string) // pem
	identifier := d.Get("identifier").(string)
	signatureRSA := d.Get("signatureRSA").(string)

	// create new user
	userData := &helpers.UserDetails{
		UserEmail:                  "",
		TempUserEmail:              "",
		GuardianEmail1:             "",
		TempGuardianEmail1:         "",
		GuardianEmail2:             "",
		TempGuardianEmail2:         "",
		GuardianEmail3:             "",
		TempGuardianEmail3:         "",
		UserMobile:                 "",
		TempUserMobile:             "",
		UserRSAPublicKey:           userRSAPublicKey,
		Secret:                     "",
		Identifier:                 identifier,
		IsRestoreInProgress:        false,
		EmailVerificationState:     false,
		MobileVerificationState:    false,
		EmailVerificationOTP:       "xxxxxx",
		MobileVerificationOTP:      "xxxxxx",
		EmailOTPGenerateTimestamp:  int64(0),
		MobileOTPGenerateTimestamp: int64(0),
		RestoreInitiationTimestamp: int64(0),
	}

	// Generate unsigned data
	unsignedData := identifier

	// verify if request is valid
	verificationErr := helpers.VerifySignedData(signatureRSA, string(unsignedData), userRSAPublicKey)
	if verificationErr == false {
		return &logical.Response{
			Data: map[string]interface{}{
				"status": "verification failed",
			},
		}, errors.New("could not verify your signature")
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
			"status": true,
		},
	}, nil
}
