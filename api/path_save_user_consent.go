package api

import (
	"cloud.google.com/go/pubsub"
	"context"
	"encoding/json"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryadavDeqode/dq-vault/api/helpers"
	"github.com/ryadavDeqode/dq-vault/config"
	"github.com/ryadavDeqode/dq-vault/logger"
	"net/http"
	"os"
)

// pathPassphrase corresponds to POST gen/passphrase.
func (b *backend) pathSaveUserConsent(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// var err error
	backendLogger := b.logger

	// obtain details:
	identifier := d.Get("identifier").(string)
	consentType := d.Get("consentType").(string)
	consent := d.Get("consent").(string)
	//signatureRSA := d.Get("signatureRSA").(string)
	signatureECDSA := d.Get("signatureECDSA").(string)

	// path where user data is stored
	path := config.StorageBasePath + identifier
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		logger.Log(backendLogger, config.Error, "saveUserConsent: could not fetch data from storage", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	// Get User data
	var userData helpers.UserDetails
	err = entry.DecodeJSON(&userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "saveUserConsent: could not encode JSON", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	dataToValidate := map[string]string{
		"identifier":  identifier,
		"consent":     consent,
		"consentType": consentType,
	}

	//rsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureRSA, dataToValidate, userData.UserRSAPublicKey, "RS256")
	//
	//if rsaVerificationState == false {
	//	return &logical.Response{
	//		Data: map[string]interface{}{
	//			"status":  false,
	//			"remarks": remarks,
	//		},
	//	}, nil
	//}

	ecdsaVerificationState, remarks := helpers.VerifyJWTSignature(signatureECDSA, dataToValidate, userData.UserECDSAPublicKey, "ES256")

	if ecdsaVerificationState == false {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": remarks,
			},
		}, nil
	}
	if consentType == "MNEMONICS" {
		userData.SignedConsentForMnemonics = consent
	} else if consentType == "PRIVATE_KEY" {
		userData.SignedConsentForPrivateKey = consent
	} else {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": "please provide valid consent type!",
			},
		}, nil
	}

	store, err := logical.StorageEntryJSON(path, userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "saveUserConsent: could not get storage entry", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// put user information in store
	if err = req.Storage.Put(ctx, store); err != nil {
		logger.Log(backendLogger, config.Error, "saveUserConsent: could not put user information in store", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	newCtx := context.Background()
	pubsubTopic := os.Getenv("PUBSUB_TOPIC")
	gcpProject := os.Getenv("GCP_PROJECT")
	client, err := pubsub.NewClient(ctx, gcpProject)
	if err != nil {
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}
	t := client.Topic(pubsubTopic)

	mailFormat := &helpers.MailFormatGuardianVerified{To: userData.UserEmail, Purpose: "USER_CONSENT_RECEIVED", MFASource: "email"}
	mailFormatJson, _ := json.Marshal(mailFormat)
	res := t.Publish(newCtx, &pubsub.Message{Data: mailFormatJson})
	_, err = res.Get(newCtx)
	if err != nil {
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}
	store, storageErr := logical.StorageEntryJSON(path, userData)
	if storageErr != nil {
		logger.Log(backendLogger, config.Error, "saveUserConsent: could not get storage entry", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// put user information in store
	if err = req.Storage.Put(ctx, store); err != nil {
		logger.Log(backendLogger, config.Error, "saveUserConsent: could not put user info in storage", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}
	// return response
	return &logical.Response{
		Data: map[string]interface{}{
			"status":  true,
			"remarks": "user consent received!",
		},
	}, nil
}
