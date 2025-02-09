package api

import (
	"cloud.google.com/go/pubsub"
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/alfred-hq/dq-vault/api/helpers"
	"github.com/alfred-hq/dq-vault/config"
	"github.com/alfred-hq/dq-vault/logger"
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
		logger.Log(backendLogger, config.Error, "submitOTP: could not get storage entry", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	newCtx := context.Background()
	pubsubTopic := os.Getenv("PUBSUB_TOPIC")
	gcpProject := os.Getenv("GCP_PROJECT")
	client, err := pubsub.NewClient(ctx, gcpProject)
	if err != nil {
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}
	t := client.Topic(pubsubTopic)

	// Get User data
	var userData helpers.UserDetails
	err = entry.DecodeJSON(&userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "submitOTP: could not get user data", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	dataToValidate := map[string]string{}

	dataToValidate = map[string]string{
		"identifier": identifier,
		"otp":        otp,
		"purpose":    purpose,
	}

	otpTTLStr := os.Getenv("OTP_TTL")
	otpTTL, err := strconv.Atoi(otpTTLStr)
	if err != nil {
		logger.Log(backendLogger, config.Error, "submitOTP: could not convert number to string", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	id := uuid.New()
	restorationId := id.String()

	gid1 := uuid.New().String()
	gid2 := uuid.New().String()
	gid3 := uuid.New().String()

	switch purpose {
	case helpers.PurposeType[0]:
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
		} else if currentUnixTime-userData.PrimaryEmailOTPGenerateTimestamp > int64(otpTTL) { // 5 minute time based otp
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
	case helpers.PurposeType[1]:
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
		} else if currentUnixTime-userData.MobileOTPGenerateTimestamp > int64(otpTTL) { // 5 minute time based otp
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
	case helpers.PurposeType[2]:
		rsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureRSA, dataToValidate, userData.UserRSAPublicKey, "RS256")

		if rsaVerificationState == false {
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
		} else if currentUnixTime-userData.PrimaryEmailOTPGenerateTimestamp > int64(otpTTL) { // 5 minute time based otp
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "OTP EXPIRED",
				},
			}, nil
		} else {
			restorationIds := &helpers.RestorationIdentifiers{
				UserRestorationIdentifier:     restorationId,
				GuardianRestorationIdentifier: []string{gid1, gid2, gid3},
			}

			storagePath := config.StorageBasePath + identifier + "restorationIdentifiers"
			store, err := logical.StorageEntryJSON(storagePath, restorationIds)
			if err != nil {
				logger.Log(backendLogger, config.Error, "restorationIdentifiers: could not create storage entry", err.Error())
				return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
			}

			// put user information in store
			if err = req.Storage.Put(ctx, store); err != nil {
				logger.Log(backendLogger, config.Error, "restorationIdentifiers: could not put user info in storage", err.Error())
				return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
			}

			userData.IsRestoreInProgress = true
			userData.RestoreInitiationTimestamp = time.Now().Unix()
			userData.PrimaryEmailVerificationOTP = "xxxxxx"
			userData.PrimaryEmailOTPGenerateTimestamp = int64(0)
			ct := time.Now()
			currentTime := ct.Format("3:04 PM")
			timeOfRestoration := time.Unix(time.Now().Unix(), 0).Format(time.RFC3339)
			mailFormatUser := &helpers.MAILFormatUpdates{userData.UserEmail, "RESTORATION_INITIATED", "email", currentTime, userData.UserWalletAddress, restorationId, userData.Identifier}
			mailFormatUserJson, _ := json.Marshal(mailFormatUser)
			res := t.Publish(newCtx, &pubsub.Message{Data: mailFormatUserJson})
			if userData.Guardians[0] != "" {
				mailFormatGuardian := &helpers.MailFormatGuardian{userData.Guardians[0], "GUARDIAN_VETO", userData.Identifier, userData.GuardianIdentifiers[0], "email", currentTime, timeOfRestoration, userData.UserEmail, userData.UserWalletAddress, gid1}
				mailFormatGuardianJson, _ := json.Marshal(mailFormatGuardian)
				res = t.Publish(newCtx, &pubsub.Message{Data: mailFormatGuardianJson})
			}
			if userData.Guardians[1] != "" {
				mailFormatGuardian := &helpers.MailFormatGuardian{userData.Guardians[1], "GUARDIAN_VETO", userData.Identifier, userData.GuardianIdentifiers[1], "email", currentTime, timeOfRestoration, userData.UserEmail, userData.UserWalletAddress, gid2}
				mailFormatGuardianJson, _ := json.Marshal(mailFormatGuardian)
				res = t.Publish(newCtx, &pubsub.Message{Data: mailFormatGuardianJson})
			}
			if userData.Guardians[2] != "" {
				mailFormatGuardian := &helpers.MailFormatGuardian{userData.Guardians[2], "GUARDIAN_VETO", userData.Identifier, userData.GuardianIdentifiers[2], "email", currentTime, timeOfRestoration, userData.UserEmail, userData.UserWalletAddress, gid3}
				mailFormatGuardianJson, _ := json.Marshal(mailFormatGuardian)
				res = t.Publish(newCtx, &pubsub.Message{Data: mailFormatGuardianJson})
			}

			_, err = res.Get(newCtx)
			if err != nil {
				return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
			}
		}
	case helpers.PurposeType[3]:
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
		} else if currentUnixTime-userData.PrimaryEmailOTPGenerateTimestamp > int64(otpTTL) { // 5 minute time based otp
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "OTP EXPIRED",
				},
			}, nil
		} else {
			userData.WalletThirdShard = userData.UnverifiedWalletThirdShard
			userData.LastRecoverySavedAt.GoogleDriveFileId = ""
			userData.LastRecoverySavedAt.IcloudFileId = ""
			userData.LastRecoverySavedAt.LocalFileId = ""
			userData.UnverifiedWalletThirdShard = ""
			userData.PrimaryEmailOTPGenerateTimestamp = int64(0)
			userData.PrimaryEmailVerificationOTP = "xxxxxx"
		}
	case helpers.PurposeType[4]:
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
		} else if currentUnixTime-userData.PrimaryEmailOTPGenerateTimestamp > int64(otpTTL) { // 5 minute time based otp
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
	case helpers.PurposeType[5]:
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
		} else if currentUnixTime-userData.MobileOTPGenerateTimestamp > int64(otpTTL) { // 5 minute time based otp
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
	case helpers.PurposeType[6]:
		rsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureRSA, dataToValidate, userData.UserRSAPublicKey, "RS256")

		if rsaVerificationState == false {
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
		} else if currentUnixTime-userData.MobileOTPGenerateTimestamp > int64(otpTTL) { // 5 minute time based otp
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "OTP EXPIRED",
				},
			}, nil
		} else {
			restorationIds := &helpers.RestorationIdentifiers{
				UserRestorationIdentifier:     restorationId,
				GuardianRestorationIdentifier: []string{gid1, gid2, gid3},
			}

			storagePath := config.StorageBasePath + identifier + "restorationIdentifiers"
			store, err := logical.StorageEntryJSON(storagePath, restorationIds)
			if err != nil {
				logger.Log(backendLogger, config.Error, "restorationIdentifiers: could not create storage entry", err.Error())
				return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
			}

			// put user information in store
			if err = req.Storage.Put(ctx, store); err != nil {
				logger.Log(backendLogger, config.Error, "restorationIdentifiers: could not put user info in storage", err.Error())
				return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
			}
			userData.IsRestoreInProgress = true
			userData.RestoreInitiationTimestamp = time.Now().Unix()
			userData.MobileVerificationOTP = "xxxxxx"
			userData.MobileOTPGenerateTimestamp = int64(0)
			ct := time.Now()
			currentTime := ct.Format("3:04 PM")
			timeOfRestoration := time.Unix(time.Now().Unix(), 0).Format(time.RFC3339)
			mailFormatUser := &helpers.MAILFormatUpdates{userData.UserEmail, "RESTORATION_INITIATED", "email", currentTime, userData.UserWalletAddress, restorationId, userData.Identifier}
			mailFormatUserJson, _ := json.Marshal(mailFormatUser)
			res := t.Publish(newCtx, &pubsub.Message{Data: mailFormatUserJson})
			if userData.Guardians[0] != "" {
				mailFormatGuardian := &helpers.MailFormatGuardian{userData.Guardians[0], "GUARDIAN_VETO", userData.Identifier, userData.GuardianIdentifiers[0], "email", currentTime, timeOfRestoration, userData.UserEmail, userData.UserWalletAddress, gid1}
				mailFormatGuardianJson, _ := json.Marshal(mailFormatGuardian)
				res = t.Publish(newCtx, &pubsub.Message{Data: mailFormatGuardianJson})
			}
			if userData.Guardians[1] != "" {
				mailFormatGuardian := &helpers.MailFormatGuardian{userData.Guardians[1], "GUARDIAN_VETO", userData.Identifier, userData.GuardianIdentifiers[1], "email", currentTime, timeOfRestoration, userData.UserEmail, userData.UserWalletAddress, gid2}
				mailFormatGuardianJson, _ := json.Marshal(mailFormatGuardian)
				res = t.Publish(newCtx, &pubsub.Message{Data: mailFormatGuardianJson})
			}
			if userData.Guardians[2] != "" {
				mailFormatGuardian := &helpers.MailFormatGuardian{userData.Guardians[2], "GUARDIAN_VETO", userData.Identifier, userData.GuardianIdentifiers[2], "email", currentTime, timeOfRestoration, userData.UserEmail, userData.UserWalletAddress, gid3}
				mailFormatGuardianJson, _ := json.Marshal(mailFormatGuardian)
				res = t.Publish(newCtx, &pubsub.Message{Data: mailFormatGuardianJson})
			}

			_, err = res.Get(newCtx)
			if err != nil {
				return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
			}
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
