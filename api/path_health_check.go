package api

import (
	"cloud.google.com/go/pubsub"
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"os"
)

// pathPassphrase corresponds to POST gen/passphrase.
func (b *backend) pathHealthCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	// check if pubsub working
	pubsubTopic := os.Getenv("PUBSUB_TOPIC")
	gcpProject := os.Getenv("GCP_PROJECT")
	newCtx := context.Background()
	client, err := pubsub.NewClient(ctx, gcpProject)
	if err != nil {
		return &logical.Response{
			Data: map[string]interface{}{
				"status": false,
			},
		}, nil
	}
	t := client.Topic(pubsubTopic)
	res := t.Publish(newCtx, &pubsub.Message{Data: []byte("health_check")})
	_, err = res.Get(ctx)
	if err != nil {
		return &logical.Response{
			Data: map[string]interface{}{
				"status": false,
			},
		}, nil
	}

	// return response
	return &logical.Response{
		Data: map[string]interface{}{
			"status": true,
		},
	}, nil
}
