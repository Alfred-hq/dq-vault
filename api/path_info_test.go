package api

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestPathInfo(t *testing.T) {

	b := backend{}
	req := logical.Request{}

	_, err := b.pathInfo(context.Background(), &req, &framework.FieldData{})

	if err != nil{

		t.Error("expected error to be nil, received - ", err)
	}
}
