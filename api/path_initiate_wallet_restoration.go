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
func (b *backend) pathInitiateWalletRestoration(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// var err error
	backendLogger := b.logger
	workDir, _ := os.Getwd()
	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", workDir+"/key.json")

	// obtain details:
	identifier := d.Get("identifier").(string)
	signatureRSA := d.Get("signatureRSA").(string)

	// path where user data is stored
	path := config.StorageBasePath + identifier
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		logger.Log(backendLogger, config.Error, "initiateWalletRestoration:", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	// Get User data
	var userData helpers.UserDetails
	err = entry.DecodeJSON(&userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "initiateWalletRestoration:", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	dataToValidate := map[string]string{
		"identifier": identifier,
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

	otp, err := helpers.GenerateOTP(6)
	if err != nil {
		logger.Log(backendLogger, config.Error, "initiateWalletRestoration:", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	userData.PrimaryEmailVerificationOTP = otp
	userData.PrimaryEmailOTPGenerateTimestamp = time.Now().Unix()

	store, err := logical.StorageEntryJSON(path, userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "initiateWalletRestoration:", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// put user information in store
	if err = req.Storage.Put(ctx, store); err != nil {
		logger.Log(backendLogger, config.Error, "initiateWalletRestoration:", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	mailFormat := &helpers.MailFormatVerification{userData.UserEmail, otp, "VERIFICATION", "email"}
	mailFormatJson, _ := json.Marshal(mailFormat)

	newCtx := context.Background()
	client, err := pubsub.NewClient(ctx, "ethos-dev-deqode") // env var
	if err != nil {
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}
	t := client.Topic("twilio-service")
	res := t.Publish(newCtx, &pubsub.Message{Data: mailFormatJson})
	_, pubsubErr := res.Get(newCtx)
	if err != nil {
		return nil, logical.CodedError(http.StatusUnprocessableEntity, pubsubErr.Error())
	}

	// return response
	return &logical.Response{
		Data: map[string]interface{}{
			"status":  true,
			"remarks": "success",
		},
	}, nil
}
