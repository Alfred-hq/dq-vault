package api

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathPassphrase corresponds to POST gen/passphrase.
func (b *backend) pathHealthCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// return response
	return &logical.Response{
		Data: map[string]interface{}{
			"status": true,
		},
	}, nil
}
