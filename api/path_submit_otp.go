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
func (b *backend) pathSubmitOTP(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// var err error
	backendLogger := b.logger

	// obtain details:
	identifier := d.Get("identifier").(string)
	service := d.Get("purpose").(string)
	signatureRSA := d.Get("signatureRSA").(string)
	otp := d.Get("otp").(string)

	// path where user data is stored
	path := config.StorageBasePath + identifier
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		logger.Log(backendLogger, config.Error, "submitOTP:", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	// Get User data
	var userData helpers.UserDetails
	err = entry.DecodeJSON(&userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "submitOTP:", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	// Generate unsigned data
	unsignedData := identifier + service

	// verify if request is valid
	verificationStatus := helpers.VerifySignedData(signatureRSA, string(unsignedData), userData.UserRSAPublicKey)
	if verificationStatus == false {
		return &logical.Response{
			Data: map[string]interface{}{
				"status": "verification failed",
			},
		}, errors.New("could not verify your signature")
	}

	switch service {
	case "ADD_OR_UPDATE_PRIMARY_EMAIL":
		currentUnixTime := time.Now().Unix()
		if userData.EmailVerificationOTP != otp {
			return nil, errors.New("OTP DID NOT MATCH")
		} else if currentUnixTime-userData.EmailOTPGenerateTimestamp > 300 { // 5 minute time based otp
			return nil, errors.New("OTP EXPIRED")
		} else {
			userData.EmailVerificationState = false
			userData.UserEmail = userData.TempUserEmail
			userData.EmailVerificationOTP = "xxxxxx"

		}
	case "ADD_OR_UPDATE_GUARDIAN_EMAIL_1":
		currentUnixTime := time.Now().Unix()
		if userData.EmailVerificationOTP != otp {
			return nil, errors.New("OTP DID NOT MATCH")
		} else if currentUnixTime-userData.EmailOTPGenerateTimestamp > 300 { // 5 minute time based otp
			return nil, errors.New("OTP EXPIRED")
		} else {
			userData.EmailVerificationState = false
			userData.GuardianEmail1 = userData.TempGuardianEmail1
			userData.EmailVerificationOTP = "xxxxxx"

		}
	case "ADD_OR_UPDATE_GUARDIAN_EMAIL_2":
		currentUnixTime := time.Now().Unix()
		if userData.EmailVerificationOTP != otp {
			return nil, errors.New("OTP DID NOT MATCH")
		} else if currentUnixTime-userData.EmailOTPGenerateTimestamp > 300 { // 5 minute time based otp
			return nil, errors.New("OTP EXPIRED")
		} else {
			userData.EmailVerificationState = false
			userData.GuardianEmail2 = userData.TempGuardianEmail2
			userData.EmailVerificationOTP = "xxxxxx"

		}
	case "ADD_OR_UPDATE_GUARDIAN_EMAIL_3":
		currentUnixTime := time.Now().Unix()
		if userData.EmailVerificationOTP != otp {
			return nil, errors.New("OTP DID NOT MATCH")
		} else if currentUnixTime-userData.EmailOTPGenerateTimestamp > 300 { // 5 minute time based otp
			return nil, errors.New("OTP EXPIRED")
		} else {
			userData.EmailVerificationState = false
			userData.GuardianEmail3 = userData.TempGuardianEmail3
			userData.EmailVerificationOTP = "xxxxxx"

		}
	case "ADD_OR_UPDATE_MOBILE_NUMBER":
		currentUnixTime := time.Now().Unix()
		if userData.MobileVerificationOTP != otp {
			return nil, errors.New("OTP DID NOT MATCH")
		} else if currentUnixTime-userData.MobileOTPGenerateTimestamp > 300 { // 5 minute time based otp
			return nil, errors.New("OTP EXPIRED")
		} else {
			userData.MobileVerificationState = false
			userData.UserMobile = userData.TempUserMobile
			userData.EmailVerificationOTP = "xxxxxx"
		}
	case "VERIFY_EMAIL_OTP":
		currentUnixTime := time.Now().Unix()
		if userData.EmailVerificationOTP != otp {
			return nil, errors.New("OTP DID NOT MATCH")
		} else if currentUnixTime-userData.MobileOTPGenerateTimestamp > 300 { // 5 minute time based otp
			return nil, errors.New("OTP EXPIRED")
		} else {
			userData.EmailVerificationState = false
			userData.EmailVerificationOTP = "xxxxxx"
		}
	case "VERIFY_MOBILE_OTP":
		currentUnixTime := time.Now().Unix()
		if userData.MobileVerificationOTP != otp {
			return nil, errors.New("OTP DID NOT MATCH")
		} else if currentUnixTime-userData.MobileOTPGenerateTimestamp > 300 { // 5 minute time based otp
			return nil, errors.New("OTP EXPIRED")
		} else {
			userData.MobileVerificationState = false
			userData.MobileVerificationOTP = "xxxxxx"
		}
	}

	store, err := logical.StorageEntryJSON(path, userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "submitOTP:", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// put user information in store
	if err = req.Storage.Put(ctx, store); err != nil {
		logger.Log(backendLogger, config.Error, "submitOTP:", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"status": true,
		},
	}, nil
}
