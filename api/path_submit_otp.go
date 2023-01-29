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
	purpose := d.Get("purpose").(string)
	signatureRSA := d.Get("signatureRSA").(string)
	signatureECDSA := d.Get("signatureECDSA").(string)
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
	unsignedData := identifier + purpose + otp

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

	switch purpose {
	case "ADD_OR_UPDATE_PRIMARY_EMAIL":
		if ecdsaVerificationState == false {
			return &logical.Response{
				Data: map[string]interface{}{
					"status": false,
					"reason": "ecdsa signature verification failed",
				},
			}, nil
		}
		currentUnixTime := time.Now().Unix()
		if userData.EmailVerificationOTP != otp {
			return nil, errors.New("OTP DID NOT MATCH")
		} else if currentUnixTime-userData.EmailOTPGenerateTimestamp > 300 { // 5 minute time based otp
			return nil, errors.New("OTP EXPIRED")
		} else {
			userData.EmailVerificationState = false
			userData.UserEmail = userData.UnverifiedUserEmail
			userData.EmailVerificationOTP = "xxxxxx"

		}
	case "ADD_OR_UPDATE_GUARDIAN_EMAIL_1":
		if ecdsaVerificationState == false {
			return &logical.Response{
				Data: map[string]interface{}{
					"status": false,
					"reason": "ecdsa signature verification failed",
				},
			}, nil
		}
		currentUnixTime := time.Now().Unix()
		if userData.EmailVerificationOTP != otp {
			return nil, errors.New("OTP DID NOT MATCH")
		} else if currentUnixTime-userData.EmailOTPGenerateTimestamp > 300 { // 5 minute time based otp
			return nil, errors.New("OTP EXPIRED")
		} else {
			userData.EmailVerificationState = false
			userData.GuardianEmail1 = userData.UnverifiedGuardianEmail1
			userData.EmailVerificationOTP = "xxxxxx"

		}
	case "ADD_OR_UPDATE_GUARDIAN_EMAIL_2":
		if ecdsaVerificationState == false {
			return &logical.Response{
				Data: map[string]interface{}{
					"status": false,
					"reason": "ecdsa signature verification failed",
				},
			}, nil
		}
		currentUnixTime := time.Now().Unix()
		if userData.EmailVerificationOTP != otp {
			return nil, errors.New("OTP DID NOT MATCH")
		} else if currentUnixTime-userData.EmailOTPGenerateTimestamp > 300 { // 5 minute time based otp
			return nil, errors.New("OTP EXPIRED")
		} else {
			userData.EmailVerificationState = false
			userData.GuardianEmail2 = userData.UnverifiedGuardianEmail2
			userData.EmailVerificationOTP = "xxxxxx"

		}
	case "ADD_OR_UPDATE_GUARDIAN_EMAIL_3":
		if ecdsaVerificationState == false {
			return &logical.Response{
				Data: map[string]interface{}{
					"status": false,
					"reason": "ecdsa signature verification failed",
				},
			}, nil
		}
		currentUnixTime := time.Now().Unix()
		if userData.EmailVerificationOTP != otp {
			return nil, errors.New("OTP DID NOT MATCH")
		} else if currentUnixTime-userData.EmailOTPGenerateTimestamp > 300 { // 5 minute time based otp
			return nil, errors.New("OTP EXPIRED")
		} else {
			userData.EmailVerificationState = false
			userData.GuardianEmail3 = userData.UnverifiedGuardianEmail3
			userData.EmailVerificationOTP = "xxxxxx"

		}
	case "ADD_OR_UPDATE_MOBILE_NUMBER":
		if ecdsaVerificationState == false {
			return &logical.Response{
				Data: map[string]interface{}{
					"status": false,
					"reason": "ecdsa signature verification failed",
				},
			}, nil
		}
		currentUnixTime := time.Now().Unix()
		if userData.MobileVerificationOTP != otp {
			return nil, errors.New("OTP DID NOT MATCH")
		} else if currentUnixTime-userData.MobileOTPGenerateTimestamp > 300 { // 5 minute time based otp
			return nil, errors.New("OTP EXPIRED")
		} else {
			userData.MobileVerificationState = false
			userData.UserMobile = userData.UnverifiedUserMobile
			userData.EmailVerificationOTP = "xxxxxx"
		}
	case "VERIFY_EMAIL_FOR_WALLET_RESTORATION":
		currentUnixTime := time.Now().Unix()
		if userData.EmailVerificationOTP != otp {
			return nil, errors.New("OTP DID NOT MATCH")
		} else if currentUnixTime-userData.EmailOTPGenerateTimestamp > 300 { // 5 minute time based otp
			return nil, errors.New("OTP EXPIRED")
		} else {
			userData.IsRestoreInProgress = true
			userData.RestoreInitiationTimestamp = time.Now().Unix()
			userData.EmailVerificationState = false
			userData.EmailVerificationOTP = "xxxxxx"
		}

	case "VERIFY_EMAIL_OTP":
		if ecdsaVerificationState == false {
			return &logical.Response{
				Data: map[string]interface{}{
					"status": false,
					"reason": "ecdsa signature verification failed",
				},
			}, nil
		}
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
		if ecdsaVerificationState == false {
			return &logical.Response{
				Data: map[string]interface{}{
					"status": false,
					"reason": "ecdsa signature verification failed",
				},
			}, nil
		}
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
