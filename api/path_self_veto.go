package api

import (
	"context"
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
func (b *backend) pathSelfVeto(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// var err error
	backendLogger := b.logger

	// obtain details:
	identifier := d.Get("identifier").(string)
	restorationIdentifier := d.Get("restorationIdentifier").(string)

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

	restorationIdentifierPath := config.StorageBasePath + identifier + "restorationIdentifiers"
	restorationEntry, err := req.Storage.Get(ctx, restorationIdentifierPath)
	if err != nil {
		logger.Log(backendLogger, config.Error, "veto: could not get storage entry", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	var restorationIds helpers.RestorationIdentifiers
	err = restorationEntry.DecodeJSON(&restorationIds)
	if err != nil {
		logger.Log(backendLogger, config.Error, "veto: could not get user details", err.Error())
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	if restorationIds.UserRestorationIdentifier != restorationIdentifier {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": "Link Expired",
			},
		}, nil
	}

	if !userData.IsRestoreInProgress {
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

	if userData.IsRestoreInProgress && userData.RestoreInitiationTimestamp+int64(waitPeriodInt) <= currentUnixTime {
		return &logical.Response{
			Data: map[string]interface{}{
				"status":  false,
				"remarks": "wallet already restored",
			},
		}, nil
	}

	userData.IsRestoreInProgress = false
	userData.RestoreInitiationTimestamp = int64(0)
	userData.LastVetoedAt = time.Now().Unix()
	userData.LastVetoedBy = "SELF"
	store, err := logical.StorageEntryJSON(path, userData)

	// put user information in store
	if err = req.Storage.Put(ctx, store); err != nil {
		logger.Log(backendLogger, config.Error, "veto: could not store user info", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// return response
	return &logical.Response{
		Data: map[string]interface{}{
			"status":  true,
			"remarks": "wallet restoration cancelled",
		},
	}, nil
}
