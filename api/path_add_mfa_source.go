package api

import (
	"cloud.google.com/go/pubsub"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"time"

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
	guardianIndex := d.Get("guardianIndex").(string)

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
		logger.Log(backendLogger, config.Error, "addMFASource:", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	if userData.IsRestoreInProgress == true {

		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": "Permission Denied because wallet restoration in progress!!",
			},
		}, nil
	}

	dataToValidate := map[string]string{}

	if sourceType == "guardianEmail" {
		dataToValidate = map[string]string{
			"identifier":    identifier,
			"sourceType":    sourceType,
			"sourceValue":   sourceValue,
			"guardianIndex": guardianIndex,
		}
	} else {
		dataToValidate = map[string]string{
			"identifier":  identifier,
			"sourceType":  sourceType,
			"sourceValue": sourceValue,
		}
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

	ecdsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureECDSA, dataToValidate, userData.UserECDSAPublicKey, "ES256")

	if ecdsaVerificationState == false {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": remarks,
			},
		}, nil
	}

	otp, err := helpers.GenerateOTP(6)
	if err != nil {
		logger.Log(backendLogger, config.Error, "addMFASource:", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	pubsubTopic := os.Getenv("PUBSUB_TOPIC")
	gcpProject := os.Getenv("GCP_PROJECT")
	newCtx := context.Background()
	client, err := pubsub.NewClient(ctx, gcpProject)
	if err != nil {
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}
	t := client.Topic(pubsubTopic)
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

	case "guardianEmail":
		index, err := strconv.Atoi(guardianIndex)
		if err != nil {
			logger.Log(backendLogger, config.Error, "updateGuardian: could not convert str to int", err.Error())
			return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
		}

		if userData.UserEmail == sourceValue {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "Primary email cannot be set as guardian!",
				},
			}, nil
		}

		if helpers.StringInSlice(sourceValue, userData.Guardians) {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "Guardian already added!",
				},
			}, nil
		}

		if sourceValue == "" {
			switch index {
			case 0:
				userData.Guardians[0] = userData.Guardians[1]
				userData.GuardianIdentifiers[0] = userData.GuardianIdentifiers[1]
				userData.Guardians[1] = userData.Guardians[2]
				userData.GuardianIdentifiers[1] = userData.GuardianIdentifiers[2]
				userData.Guardians[2] = ""
				userData.GuardianIdentifiers[2] = ""
			case 1:
				userData.Guardians[1] = userData.Guardians[2]
				userData.GuardianIdentifiers[1] = userData.GuardianIdentifiers[2]
				userData.Guardians[2] = ""
				userData.GuardianIdentifiers[2] = ""
			case 2:
				userData.Guardians[2] = ""
				userData.GuardianIdentifiers[2] = ""
			}
		} else {
			userData.UnverifiedGuardians[index] = sourceValue
			userData.GuardiansAddLinkInitiation[index] = time.Now().Unix()
			guardianLinkPath := base64.StdEncoding.EncodeToString([]byte(userData.Identifier + "_" + strconv.Itoa(index) + "_" + sourceValue))
			mailFormat := &helpers.MailFormatGuardianAdditionLink{To: sourceValue, Purpose: "ADD_GUARDIAN", MFASource: "email", WalletIdentifier: identifier, Path: guardianLinkPath}
			mailFormatJson, _ := json.Marshal(mailFormat)
			res := t.Publish(newCtx, &pubsub.Message{Data: mailFormatJson})
			_, err = res.Get(newCtx)
			if err != nil {
				return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
			}
		}
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
