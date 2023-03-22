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
func (b *backend) pathVeto(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// var err error
	backendLogger := b.logger

	// obtain details:
	identifier := d.Get("identifier").(string)
	guardianIdentifier := d.Get("guardianIdentifier").(string)

	// path where user data is stored
	path := config.StorageBasePath + identifier
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		logger.Log(backendLogger, config.Error, "veto: could not get storage entry", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	// Get User data
	var userData helpers.UserDetails
	err = entry.DecodeJSON(&userData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "veto: could not get user details", err.Error())
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
	for index, guardian := range userData.GuardianIdentifiers {
		if guardian == guardianIdentifier {
			if userData.IsRestoreInProgress == false {
				return &logical.Response{
					Data: map[string]interface{}{
						"status":  false,
						"remarks": "Either wallet restored or vetoed by other guardian",
					},
				}, nil
			}

			waitPeriod := os.Getenv("WAIT_PERIOD")
			waitPeriodInt, err := strconv.Atoi(waitPeriod)

			currentUnixTime := time.Now().Unix()
			if userData.IsRestoreInProgress == true && userData.RestoreInitiationTimestamp+int64(waitPeriodInt) <= currentUnixTime {
				return &logical.Response{
					Data: map[string]interface{}{
						"status":  false,
						"remarks": "wallet already restored",
					},
				}, nil
			}
			userData.IsRestoreInProgress = false
			userData.RestoreInitiationTimestamp = int64(0)
			userData.LastVetoedBy = userData.Guardians[index]
			store, err := logical.StorageEntryJSON(path, userData)

			mailFormatUser := &helpers.MailFormatVetoed{userData.UserEmail, "RESTORATION_VETOED", userData.Guardians[index], "email"}
			mailFormatUserJson, _ := json.Marshal(mailFormatUser)
			res := t.Publish(newCtx, &pubsub.Message{Data: mailFormatUserJson})
			_, err = res.Get(newCtx)
			if err != nil {
				return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
			}

			// put user information in store
			if err = req.Storage.Put(ctx, store); err != nil {
				logger.Log(backendLogger, config.Error, "veto: could not store user info", err.Error())
				return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
			}

			return &logical.Response{
				Data: map[string]interface{}{
					"status":  true,
					"remarks": "wallet restoration cancelled",
				},
			}, nil

		}
	}

	// return response
	return &logical.Response{
		Data: map[string]interface{}{
			"status":  false,
			"remarks": "guardian not found",
		},
	}, nil
}
