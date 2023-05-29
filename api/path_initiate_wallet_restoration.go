package api

import (
	"cloud.google.com/go/pubsub"
	"context"
	"encoding/json"
	"os"
	"strconv"
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
func (b *backend) pathInitiateWalletRestoration(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// var err error
	backendLogger := b.logger

	// obtain details:
	identifier := d.Get("identifier").(string)
	sourceType := d.Get("sourceType").(string)
	signatureRSA := d.Get("signatureRSA").(string)

	// path where user data is stored
	path := config.StorageBasePath + identifier
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		logger.Log(backendLogger, config.Error, "initiateWalletRestoration: could not get user data from storage", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	// Get User data
	var userData helpers.UserDetails
	err = entry.DecodeJSON(&userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "initiateWalletRestoration: unable to get user data", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	dataToValidate := map[string]string{
		"identifier": identifier,
		"sourceType": sourceType,
	}

	rsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureRSA, dataToValidate, userData.UserRSAPublicKey, "RS256")

	if !rsaVerificationState {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": remarks,
			},
		}, nil
	}

	waitTimeAfterVetoStr := os.Getenv("WAIT_TIME_AFTER_VETO")

	waitTimeAfterVeto, err := strconv.Atoi(waitTimeAfterVetoStr)
	if err != nil {
		logger.Log(backendLogger, config.Error, "intiateWalletRestoration: could not convert number to string", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	currentTime := time.Now().Unix()

	if (currentTime - userData.LastVetoedAt) < int64(waitTimeAfterVeto) {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": "Vault restoration locked",
			},
		}, nil
	}

	otp, err := helpers.GenerateOTP(6)
	if err != nil {
		logger.Log(backendLogger, config.Error, "initiateWalletRestoration: unable to generate otp", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	if sourceType == "EMAIL" {
		if userData.UserEmail == "" {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "no email is associated with this account",
				},
			}, nil
		}
		userData.PrimaryEmailVerificationOTP = otp
		userData.PrimaryEmailOTPGenerateTimestamp = time.Now().Unix()
		mailFormat := &helpers.MailFormatVerification{To: userData.UserEmail, Otp: otp, Purpose: "VERIFICATION", MFASource: "email"}
		mailFormatJson, _ := json.Marshal(mailFormat)

		pubsubTopic := os.Getenv("PUBSUB_TOPIC")
		gcpProject := os.Getenv("GCP_PROJECT")

		newCtx := context.Background()
		client, err := pubsub.NewClient(ctx, gcpProject)
		if err != nil {
			return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
		}
		t := client.Topic(pubsubTopic)
		res := t.Publish(newCtx, &pubsub.Message{Data: mailFormatJson})
		_, pubsubErr := res.Get(newCtx)
		if err != nil {
			return nil, logical.CodedError(http.StatusUnprocessableEntity, pubsubErr.Error())
		}
	} else if sourceType == "MOBILE" {
		if userData.UserMobile == "" {
			return &logical.Response{
				Data: map[string]interface{}{
					"status":  false,
					"remarks": "no mobile number is associated with this account",
				},
			}, nil
		}
		userData.MobileVerificationOTP = otp
		userData.MobileOTPGenerateTimestamp = time.Now().Unix()

		mailFormat := &helpers.MailFormatVerification{userData.UserMobile, otp, "VERIFICATION", "mobile", userData.UserWalletAddress}
		mailFormatJson, _ := json.Marshal(mailFormat)

		pubsubTopic := os.Getenv("PUBSUB_TOPIC")
		gcpProject := os.Getenv("GCP_PROJECT")

		newCtx := context.Background()
		client, err := pubsub.NewClient(ctx, gcpProject)
		if err != nil {
			return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
		}
		t := client.Topic(pubsubTopic)
		res := t.Publish(newCtx, &pubsub.Message{Data: mailFormatJson})
		_, err = res.Get(newCtx)
		if err != nil {
			return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
		}
	}

	store, err := logical.StorageEntryJSON(path, userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "initiateWalletRestoration: unable to get store entry", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// put user information in store
	if err = req.Storage.Put(ctx, store); err != nil {
		logger.Log(backendLogger, config.Error, "initiateWalletRestoration: unable to store user info", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// return response
	return &logical.Response{
		Data: map[string]interface{}{
			"status":  true,
			"remarks": "success",
		},
	}, nil
}
