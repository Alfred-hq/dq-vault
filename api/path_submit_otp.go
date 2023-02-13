package api

import (
	"cloud.google.com/go/pubsub"
	"context"
	"encoding/json"
	"os"
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

	workDir, _ := os.Getwd()
	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", workDir+"/key.json")

	newCtx := context.Background()
	client, err := pubsub.NewClient(ctx, "ethos-dev-deqode")
	if err != nil {
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}
	t := client.Topic("twilio-service")

	// Get User data
	var userData helpers.UserDetails
	err = entry.DecodeJSON(&userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "submitOTP:", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	// Generate unsigned data
	unsignedData := identifier + otp + purpose // alphabetical

	// verify if request is valid
	rsaVerificationState := helpers.VerifyRSASignedMessage(signatureRSA, unsignedData, userData.UserRSAPublicKey)
	if rsaVerificationState == false {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": "rsa signature verification failed",
			},
		}, nil
	}

	ecdsaVerificationState := helpers.VerifyECDSASignedMessage(signatureECDSA, unsignedData, userData.UserECDSAPublicKey)

	switch purpose {
	case "ADD_OR_UPDATE_PRIMARY_EMAIL":
		if ecdsaVerificationState == false {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "ecdsa signature verification failed",
				},
			}, nil
		}
		currentUnixTime := time.Now().Unix()
		if userData.PrimaryEmailVerificationOTP != otp {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "OTP DID NOT MATCH",
				},
			}, nil
		} else if currentUnixTime-userData.PrimaryEmailOTPGenerateTimestamp > 300 { // 5 minute time based otp
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "OTP EXPIRED",
				},
			}, nil
		} else {
			userData.UserEmail = userData.UnverifiedUserEmail // unset values
			userData.UnverifiedUserEmail = ""
			userData.PrimaryEmailOTPGenerateTimestamp = int64(0)
			userData.PrimaryEmailVerificationOTP = "xxxxxx"
		}
	case "ADD_OR_UPDATE_GUARDIAN_EMAIL_1":
		if ecdsaVerificationState == false {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "ecdsa signature verification failed",
				},
			}, nil
		}
		currentUnixTime := time.Now().Unix()
		if userData.GuardianEmail1VerificationOTP != otp {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "OTP DID NOT MATCH",
				},
			}, nil
		} else if currentUnixTime-userData.GuardianEmail1OTPGenerateTimestamp > 300 { // 5 minute time based otp
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "OTP EXPIRED",
				},
			}, nil
		} else {
			userData.GuardianEmail1 = userData.UnverifiedGuardianEmail1
			userData.UnverifiedGuardianEmail1 = ""
			userData.GuardianEmail1OTPGenerateTimestamp = int64(0)
			userData.GuardianEmail1VerificationOTP = "xxxxxx"
		}
	case "ADD_OR_UPDATE_GUARDIAN_EMAIL_2":
		if ecdsaVerificationState == false {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "ecdsa signature verification failed",
				},
			}, nil
		}
		currentUnixTime := time.Now().Unix()
		if userData.GuardianEmail2VerificationOTP != otp {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "OTP DID NOT MATCH",
				},
			}, nil
		} else if currentUnixTime-userData.GuardianEmail2OTPGenerateTimestamp > 300 { // 5 minute time based otp
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "OTP EXPIRED",
				},
			}, nil
		} else {
			userData.GuardianEmail2 = userData.UnverifiedGuardianEmail2
			userData.UnverifiedGuardianEmail2 = ""
			userData.GuardianEmail2OTPGenerateTimestamp = int64(0)
			userData.GuardianEmail2VerificationOTP = "xxxxxx"
		}
	case "ADD_OR_UPDATE_GUARDIAN_EMAIL_3":
		if ecdsaVerificationState == false {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "ecdsa signature verification failed",
				},
			}, nil
		}
		currentUnixTime := time.Now().Unix()
		if userData.GuardianEmail3VerificationOTP != otp {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "OTP DID NOT MATCH",
				},
			}, nil
		} else if currentUnixTime-userData.GuardianEmail3OTPGenerateTimestamp > 300 { // 5 minute time based otp
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "OTP EXPIRED",
				},
			}, nil
		} else {
			userData.GuardianEmail3 = userData.UnverifiedGuardianEmail3
			userData.UnverifiedGuardianEmail3 = ""
			userData.GuardianEmail3OTPGenerateTimestamp = int64(0)
			userData.GuardianEmail3VerificationOTP = "xxxxxx"
		}
	case "ADD_OR_UPDATE_MOBILE_NUMBER":
		if ecdsaVerificationState == false {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "ecdsa signature verification failed",
				},
			}, nil
		}
		currentUnixTime := time.Now().Unix()
		if userData.MobileVerificationOTP != otp {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "OTP DID NOT MATCH",
				},
			}, nil
		} else if currentUnixTime-userData.MobileOTPGenerateTimestamp > 300 { // 5 minute time based otp
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "OTP EXPIRED",
				},
			}, nil
		} else {
			userData.UserMobile = userData.UnverifiedUserMobile
			userData.UnverifiedUserMobile = ""
			userData.MobileOTPGenerateTimestamp = int64(0)
			userData.MobileVerificationOTP = "xxxxxx"
		}
	case "VERIFY_EMAIL_FOR_WALLET_RESTORATION":
		currentUnixTime := time.Now().Unix()
		if userData.PrimaryEmailVerificationOTP != otp {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "OTP DID NOT MATCH",
				},
			}, nil
		} else if currentUnixTime-userData.PrimaryEmailOTPGenerateTimestamp > 300 { // 5 minute time based otp
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "OTP EXPIRED",
				},
			}, nil
		} else {
			userData.IsRestoreInProgress = true
			userData.RestoreInitiationTimestamp = time.Now().Unix()
			userData.PrimaryEmailVerificationOTP = "xxxxxx"
			userData.PrimaryEmailOTPGenerateTimestamp = int64(0)
			ct := time.Now()
			currentTime := ct.Format("15:04:05")
			mailFormatUser := &helpers.MAILFormatUpdates{userData.UserEmail, "RESTORATION_INITIATED", "email", currentTime}
			mailFormatUserJson, _ := json.Marshal(mailFormatUser)
			res := t.Publish(newCtx, &pubsub.Message{Data: mailFormatUserJson})
			_, err := res.Get(newCtx)
			if err != nil {
				return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
			}
		}
	case "ADD_WALLET_THIRD_SHARD":
		if ecdsaVerificationState == false {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "ecdsa signature verification failed",
				},
			}, nil
		}
		currentUnixTime := time.Now().Unix()
		if userData.PrimaryEmailVerificationOTP != otp {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "OTP DID NOT MATCH",
				},
			}, nil
		} else if currentUnixTime-userData.PrimaryEmailOTPGenerateTimestamp > 300 { // 5 minute time based otp
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "OTP EXPIRED",
				},
			}, nil
		} else {
			userData.WalletThirdShard = userData.UnverifiedWalletThirdShard // unset values
			userData.UnverifiedWalletThirdShard = ""
			userData.PrimaryEmailOTPGenerateTimestamp = int64(0)
			userData.PrimaryEmailVerificationOTP = "xxxxxx"
		}
	case "VERIFY_EMAIL_OTP":
		if ecdsaVerificationState == false {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "ecdsa signature verification failed",
				},
			}, nil
		}
		currentUnixTime := time.Now().Unix()
		if userData.PrimaryEmailVerificationOTP != otp {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "OTP DID NOT MATCH",
				},
			}, nil
		} else if currentUnixTime-userData.PrimaryEmailOTPGenerateTimestamp > 300 { // 5 minute time based otp
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "OTP EXPIRED",
				},
			}, nil
		} else {
			userData.PrimaryEmailVerificationOTP = "xxxxxx"
			userData.PrimaryEmailOTPGenerateTimestamp = int64(0)
		}
	case "VERIFY_MOBILE_OTP":
		if ecdsaVerificationState == false {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "ecdsa signature verification failed",
				},
			}, nil
		}
		currentUnixTime := time.Now().Unix()
		if userData.MobileVerificationOTP != otp {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "OTP DID NOT MATCH",
				},
			}, nil
		} else if currentUnixTime-userData.MobileOTPGenerateTimestamp > 300 { // 5 minute time based otp
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "OTP EXPIRED",
				},
			}, nil
		} else {
			userData.MobileVerificationOTP = "xxxxxx"
			userData.MobileOTPGenerateTimestamp = int64(0)
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
			"status":  true,
			"remarks": "Verified",
		},
	}, nil
}
