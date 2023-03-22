package api

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)


func TestPathGuardians(t *testing.T) {
	b := backend{}

	req := logical.Request{}
	d := framework.FieldData{}

	MPatchGet("test")


	pathGs, err := b.pathGuardians(context.Background(), &req, &d)

	

}
