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

	"github.com/google/uuid"
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
	//unsignedData := identifier + otp + purpose // alphabetical

	dataToValidate := map[string]string{
		"identifier": identifier,
		"otp":        otp,
		"purpose":    purpose,
	}

	rsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureRSA, dataToValidate, userData.UserRSAPublicKey, "RS256")

	if rsaVerificationState == false {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": remarks,
			},
		}, nil
	}

	switch purpose {
	case "ADD_OR_UPDATE_PRIMARY_EMAIL":
		ecdsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureECDSA, dataToValidate, userData.UserECDSAPublicKey, "ES256")
		if ecdsaVerificationState == false {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": remarks,
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
		ecdsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureECDSA, dataToValidate, userData.UserECDSAPublicKey, "ES256")
		if ecdsaVerificationState == false {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": remarks,
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
			id := uuid.New()
			guardianId := id.String()
			userData.GuardianIdentifiers[0] = guardianId
			userData.GuardianEmail1 = userData.UnverifiedGuardianEmail1
			userData.UnverifiedGuardianEmail1 = ""
			userData.GuardianEmail1OTPGenerateTimestamp = int64(0)
			userData.GuardianEmail1VerificationOTP = "xxxxxx"
		}
	case "ADD_OR_UPDATE_GUARDIAN_EMAIL_2":
		ecdsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureECDSA, dataToValidate, userData.UserECDSAPublicKey, "ES256")
		if ecdsaVerificationState == false {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": remarks,
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
			id := uuid.New()
			guardianId := id.String()
			userData.GuardianIdentifiers[1] = guardianId
			userData.GuardianEmail2 = userData.UnverifiedGuardianEmail2
			userData.UnverifiedGuardianEmail2 = ""
			userData.GuardianEmail2OTPGenerateTimestamp = int64(0)
			userData.GuardianEmail2VerificationOTP = "xxxxxx"
		}
	case "ADD_OR_UPDATE_GUARDIAN_EMAIL_3":
		ecdsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureECDSA, dataToValidate, userData.UserECDSAPublicKey, "ES256")
		if ecdsaVerificationState == false {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": remarks,
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
			id := uuid.New()
			guardianId := id.String()
			userData.GuardianIdentifiers[2] = guardianId
			userData.GuardianEmail3 = userData.UnverifiedGuardianEmail3
			userData.UnverifiedGuardianEmail3 = ""
			userData.GuardianEmail3OTPGenerateTimestamp = int64(0)
			userData.GuardianEmail3VerificationOTP = "xxxxxx"
		}
	case "ADD_OR_UPDATE_MOBILE_NUMBER":
		ecdsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureECDSA, dataToValidate, userData.UserECDSAPublicKey, "ES256")
		if ecdsaVerificationState == false {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": remarks,
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
			timeOfRestoration := time.Unix(time.Now().Unix(), 0).Format(time.RFC3339)
			mailFormatUser := &helpers.MAILFormatUpdates{userData.UserEmail, "RESTORATION_INITIATED", "email", currentTime}
			mailFormatUserJson, _ := json.Marshal(mailFormatUser)
			res := t.Publish(newCtx, &pubsub.Message{Data: mailFormatUserJson})
			if userData.GuardianEmail1 != "" {
				mailFormatGuardian := &helpers.MailFormatGuardian{userData.GuardianEmail1, "GUARDIAN_VETO", userData.Identifier, userData.GuardianIdentifiers[0], "email", currentTime, timeOfRestoration}
				mailFormatGuardianJson, _ := json.Marshal(mailFormatGuardian)
				res = t.Publish(newCtx, &pubsub.Message{Data: mailFormatGuardianJson})
			}
			if userData.GuardianEmail2 != "" {
				mailFormatGuardian := &helpers.MailFormatGuardian{userData.GuardianEmail2, "GUARDIAN_VETO", userData.Identifier, userData.GuardianIdentifiers[1], "email", currentTime, timeOfRestoration}
				mailFormatGuardianJson, _ := json.Marshal(mailFormatGuardian)
				res = t.Publish(newCtx, &pubsub.Message{Data: mailFormatGuardianJson})
			}
			if userData.GuardianEmail3 != "" {
				mailFormatGuardian := &helpers.MailFormatGuardian{userData.GuardianEmail3, "GUARDIAN_VETO", userData.Identifier, userData.GuardianIdentifiers[2], "email", currentTime, timeOfRestoration}
				mailFormatGuardianJson, _ := json.Marshal(mailFormatGuardian)
				res = t.Publish(newCtx, &pubsub.Message{Data: mailFormatGuardianJson})
			}

			_, err := res.Get(newCtx)
			if err != nil {
				return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
			}
		}
	case "ADD_WALLET_THIRD_SHARD":
		ecdsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureECDSA, dataToValidate, userData.UserECDSAPublicKey, "ES256")
		if ecdsaVerificationState == false {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": remarks,
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
		ecdsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureECDSA, dataToValidate, userData.UserECDSAPublicKey, "ES256")
		if ecdsaVerificationState == false {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": remarks,
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
		ecdsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureECDSA, dataToValidate, userData.UserECDSAPublicKey, "ES256")
		if ecdsaVerificationState == false {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": remarks,
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
