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

	workDir, _ := os.Getwd()
	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", workDir+"/key.json")

	// Get User data
	var userData helpers.UserDetails
	err = entry.DecodeJSON(&userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "addMFASource:", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	// Generate unsigned data
	unsignedData := identifier + sourceType + sourceValue

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

	if ecdsaVerificationState == false {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": "ecdsa signature verification failed",
			},
		}, nil
	}

	otp, err := helpers.GenerateOTP(6)
	if err != nil {
		logger.Log(backendLogger, config.Error, "addMFASource:", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	newCtx := context.Background()
	client, err := pubsub.NewClient(ctx, "ethos-dev-deqode")
	if err != nil {
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}
	t := client.Topic("twilio-service") // To-Do: add cons
	switch sourceType {
	case "userEmail":
		mailFormat := &helpers.MailFormatVerification{sourceValue, otp, "VERIFICATION", "email"}
		mailFormatJson, _ := json.Marshal(mailFormat)
		res := t.Publish(newCtx, &pubsub.Message{Data: mailFormatJson})
		_, err := res.Get(newCtx)
		if err != nil {
			return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
		}
		userData.UnverifiedUserEmail = sourceValue
		userData.PrimaryEmailVerificationOTP = otp
		userData.PrimaryEmailOTPGenerateTimestamp = time.Now().Unix()

	case "guardianEmail1":
		mailFormat := &helpers.MailFormatVerification{sourceValue, otp, "VERIFICATION", "email"}
		mailFormatJson, _ := json.Marshal(mailFormat)
		res := t.Publish(newCtx, &pubsub.Message{Data: mailFormatJson})
		_, err := res.Get(newCtx)
		if err != nil {
			return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
		}
		userData.UnverifiedGuardianEmail1 = sourceValue
		userData.GuardianEmail1VerificationOTP = otp
		userData.GuardianEmail1OTPGenerateTimestamp = time.Now().Unix()
	case "guardianEmail2":
		mailFormat := &helpers.MailFormatVerification{sourceValue, otp, "VERIFICATION", "email"}
		mailFormatJson, _ := json.Marshal(mailFormat)
		res := t.Publish(newCtx, &pubsub.Message{Data: mailFormatJson})
		_, err := res.Get(newCtx)
		if err != nil {
			return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
		}
		userData.UnverifiedGuardianEmail2 = sourceValue
		userData.GuardianEmail2VerificationOTP = otp
		userData.GuardianEmail2OTPGenerateTimestamp = time.Now().Unix()

	case "guardianEmail3":
		mailFormat := &helpers.MailFormatVerification{sourceValue, otp, "VERIFICATION", "email"}
		mailFormatJson, _ := json.Marshal(mailFormat)
		res := t.Publish(newCtx, &pubsub.Message{Data: mailFormatJson})
		_, err := res.Get(newCtx)
		if err != nil {
			return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
		}
		userData.UnverifiedGuardianEmail3 = sourceValue
		userData.GuardianEmail3VerificationOTP = otp
		userData.GuardianEmail3OTPGenerateTimestamp = time.Now().Unix()

	case "userMobileNumber":
		mailFormat := &helpers.MailFormatVerification{sourceValue, otp, "VERIFICATION", "mobile"}
		mailFormatJson, _ := json.Marshal(mailFormat)
		res := t.Publish(newCtx, &pubsub.Message{Data: mailFormatJson})
		_, err := res.Get(newCtx)
		if err != nil {
			return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
		}
		userData.UnverifiedUserMobile = sourceValue
		userData.MobileVerificationOTP = otp
		userData.MobileOTPGenerateTimestamp = time.Now().Unix()
		userData.MobileVerificationState = true
	}

	store, err := logical.StorageEntryJSON(path, userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "addMFASource:", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// put user information in store
	if err = req.Storage.Put(ctx, store); err != nil {
		logger.Log(backendLogger, config.Error, "addMFASource:", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// return response
	return &logical.Response{
		Data: map[string]interface{}{
			"status":  true,
			"remarks": "Verification OTP sent!",
		},
	}, nil
}
