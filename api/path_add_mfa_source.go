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
func (b *backend) pathAddMFASource(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// var err error
	backendLogger := b.logger

	// obtain details:
	identifier := d.Get("identifier").(string)
	sourceType := d.Get("sourceType").(string)
	signatureRSA := d.Get("signatureRSA").(string)
	signatureECDSA := d.Get("signatureECDSA").(string)
	sourceValue := d.Get("sourceValue").(string)

	// path where user data is stored
	path := config.StorageBasePath + identifier
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		logger.Log(backendLogger, config.Error, "addMFASource:", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	// Get User data
	var userData helpers.UserDetails
	err = entry.DecodeJSON(&userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "addThirdShard:", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	// Generate unsigned data
	unsignedData := identifier + sourceType + sourceValue

	// verify if request is valid
	rsaVerificationState := helpers.VerifyRSASignedMessage(signatureRSA, unsignedData, userData.UserRSAPublicKey)
	if rsaVerificationState == false {
		return &logical.Response{
			Data: map[string]interface{}{
				"status": false,
				"reason": "rsa signature verification failed",
			},
		}, nil
	}

	ecdsaVerificationState := helpers.VerifyECDSASignedMessage(signatureECDSA, unsignedData, userData.UserECDSAPublicKey)

	if ecdsaVerificationState == false {
		return &logical.Response{
			Data: map[string]interface{}{
				"status": false,
				"reason": "ecdsa signature verification failed",
			},
		}, nil
	}

	otp, err := helpers.GenerateOTP(6)
	if err != nil {
		logger.Log(backendLogger, config.Error, "addThirdShard:", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	switch sourceType {
	case "primaryEmail":
		userData.UnverifiedUserEmail = sourceValue
		userData.EmailVerificationOTP = otp
		userData.EmailOTPGenerateTimestamp = time.Now().Unix()
		userData.EmailVerificationState = true
	case "guardianEmail1":
		userData.UnverifiedGuardianEmail1 = sourceValue
		userData.EmailVerificationOTP = otp
		userData.EmailOTPGenerateTimestamp = time.Now().Unix()
		userData.EmailVerificationState = true
	case "guardianEmail2":
		userData.UnverifiedGuardianEmail2 = sourceValue
		userData.EmailVerificationOTP = otp
		userData.EmailOTPGenerateTimestamp = time.Now().Unix()
		userData.EmailVerificationState = true
	case "guardianEmail3":
		userData.UnverifiedGuardianEmail3 = sourceValue
		userData.EmailVerificationOTP = otp
		userData.EmailOTPGenerateTimestamp = time.Now().Unix()
		userData.EmailVerificationState = true
	case "userMobileNumber":
		userData.UnverifiedUserMobile = sourceValue
		userData.MobileVerificationOTP = otp
		userData.MobileOTPGenerateTimestamp = time.Now().Unix()
		userData.MobileVerificationState = true
	}

	store, err := logical.StorageEntryJSON(path, userData)
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
			"otp":    otp,
			"status": true,
		},
	}, nil
}
