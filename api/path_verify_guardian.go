package api

import (
	"cloud.google.com/go/pubsub"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/google/uuid"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryadavDeqode/dq-vault/api/helpers"
	"github.com/ryadavDeqode/dq-vault/config"
	"github.com/ryadavDeqode/dq-vault/logger"
)

// pathPassphrase corresponds to POST gen/passphrase.
func (b *backend) pathVerifyGuardian(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// var err error
	backendLogger := b.logger

	// obtain details:
	identifier := d.Get("identifier").(string)
	guardianLinkPathEncoded := d.Get("path").(string)

	guardianLinkPathDecodedBytes, err := base64.StdEncoding.DecodeString(guardianLinkPathEncoded)
	if err != nil {
		logger.Log(backendLogger, config.Error, "verifyGuardian: Malformed base64 encoded string", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	guardianLinkPath := string(guardianLinkPathDecodedBytes)

	values := strings.Split(guardianLinkPath, "_")

	if values[0] != identifier {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": "Identifier mismatch!",
			},
		}, nil
	}

	// path where user data is stored
	path := config.StorageBasePath + identifier
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		logger.Log(backendLogger, config.Error, "updateGuardian: could not fetch data from storage", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	// Get User data
	var userData helpers.UserDetails
	err = entry.DecodeJSON(&userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "updateGuardian: could not encode JSON", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	if helpers.StringInSlice(values[1], userData.Guardians) {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": "Guardian already added!",
			},
		}, nil
	}
	guardianInd := -1
	for guardianIndex, guardian := range userData.UnverifiedGuardians {
		if guardian == values[1] {
			guardianInd = guardianIndex
		}
	}

	if guardianInd == -1 {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": "Cannot verify as you have been removed as guardian!",
			},
		}, nil
	}

	if userData.UnverifiedGuardians[guardianInd] != values[1] {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": "Email mismatch!",
			},
		}, nil
	}

	expiryTime := userData.GuardiansAddLinkInitiation[guardianInd] + 604800

	if time.Now().Unix() > expiryTime {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": "Link Expired!",
			},
		}, nil
	}

	userData.Guardians[guardianInd] = userData.UnverifiedGuardians[guardianInd]
	userData.GuardiansAddLinkInitiation[guardianInd] = 0
	userData.UnverifiedGuardians[guardianInd] = ""
	id := uuid.New()
	guardianId := id.String()
	userData.GuardianIdentifiers[guardianInd] = guardianId
	store, err := logical.StorageEntryJSON(path, userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "updateGuardian: could not get storage entry", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// put user information in store
	if err = req.Storage.Put(ctx, store); err != nil {
		logger.Log(backendLogger, config.Error, "updateGuardian: could not put user information in store", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	mailFormat := &helpers.MailFormatGuardianVerified{To: userData.Guardians[guardianInd], Purpose: "VERIFY_GUARDIAN", MFASource: "email"}
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

	// return response
	return &logical.Response{
		Data: map[string]interface{}{
			"status":  true,
			"remarks": "guardian verified successfully!",
		},
	}, nil
}
