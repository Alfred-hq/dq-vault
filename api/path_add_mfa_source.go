package api

import (
	"context"
	"errors"
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
	sourceValue := d.Get("sourceValue").(string)
	//signatureECDSA := d.Get("signatureECDSA").(string)

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
	unsignedData := identifier + sourceType

	// verify if request is valid
	verificationErr := helpers.VerifySignedData(signatureRSA, string(unsignedData), userData.UserRSAPublicKey)
	if verificationErr == false {
		return &logical.Response{
			Data: map[string]interface{}{
				"status": "verification failed",
			},
		}, errors.New("could not verify your signature")
	}

	otp, err := helpers.GenerateOTP(6)
	if err != nil {
		logger.Log(backendLogger, config.Error, "addThirdShard:", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	switch sourceType {
	case "primaryEmail":
		userData.TempUserEmail = sourceValue
		userData.EmailVerificationOTP = otp
		userData.EmailOTPGenerateTimestamp = time.Now().Unix()
		userData.EmailVerificationState = true
	case "guardianEmail1":
		userData.TempGuardianEmail1 = sourceValue
		userData.EmailVerificationOTP = otp
		userData.EmailOTPGenerateTimestamp = time.Now().Unix()
		userData.EmailVerificationState = true
	case "guardianEmail2":
		userData.TempGuardianEmail2 = sourceValue
		userData.EmailVerificationOTP = otp
		userData.EmailOTPGenerateTimestamp = time.Now().Unix()
		userData.EmailVerificationState = true
	case "guardianEmail3":
		userData.TempGuardianEmail3 = sourceValue
		userData.EmailVerificationOTP = otp
		userData.EmailOTPGenerateTimestamp = time.Now().Unix()
		userData.EmailVerificationState = true
	case "userMobileNumber":
		userData.TempUserMobile = sourceValue
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
