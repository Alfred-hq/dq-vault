package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryadavDeqode/dq-vault/api/helpers"
	"github.com/ryadavDeqode/dq-vault/config"
	"github.com/ryadavDeqode/dq-vault/lib"
	"github.com/ryadavDeqode/dq-vault/logger"
)

// pathPassphrase corresponds to POST gen/passphrase.
func (b *backend) pathTest(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// var err error
	backendLogger := b.logger

	// obatin username
	randomVal := d.Get("randomDataA").(string)

	storagePath := config.StorageBasePath + randomVal

	// create object to store user information
	randData := &helpers.TestData{
		randomDataA: randomVal,
	}

	// creates strorage entry with user JSON encoded value
	store, err := logical.StorageEntryJSON(storagePath, randData)
	if err != nil {
		logger.Log(backendLogger, config.Error, "test:", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// put user information in store
	if err = req.Storage.Put(ctx, store); err != nil {
		logger.Log(backendLogger, config.Error, "test:", err.Error())
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	logger.Log(backendLogger, config.Info, "register:", fmt.Sprintf("user registered username=%v", username))

	// return response
	return &logical.Response{
		Data: map[string]interface{}{
			"newRandData": randData,
		},
	}, nil
}
