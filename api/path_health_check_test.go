package api

import (
	"context"
	"errors"
	"testing"

	// "errors"
	// "fmt"

	// "encoding/json"
	// "fmt"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryadavDeqode/dq-vault/test/unit_test/mocks"
)

// pathPassphrase corresponds to POST gen/passphrase.
func TestPathHealthCheck(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := mocks.NewMockStorage(ctrl)

	tErr := "test error"

	b := backend{}
	req := logical.Request{}

	req.Storage = s

	mpnc := MPatchNewClient(errors.New(tErr))
	res, err := b.pathHealthCheck(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error("expected no error, received", err, res)
	} else if res.Data["status"].(bool) {

		t.Error("unexpected status- ", res.Data["status"], "expected 'false' received true'")
	}

	mpnc.Unpatch()
	mpnc = MPatchNewClient(nil)

	mppublish := MPatchPublish()

	mpget := MPatchGetPubSub(tErr, errors.New(tErr))

	res, err = b.pathHealthCheck(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error("expected no error, received", err, res)
	} else if res.Data["status"].(bool) {

		t.Error("unexpected status- ", res.Data["status"], "expected 'false' received true'")
	}

	mpget.Unpatch()
	mpget = MPatchGetPubSub(tErr, nil)

	res, err = b.pathHealthCheck(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error("expected no error, received", err, res)
	} else if !res.Data["status"].(bool) {

		t.Error("unexpected status- ", res.Data["status"], "expected 'true' received false'")
	}

	mpnc.Unpatch()
	mpget.Unpatch()
	mppublish.Unpatch()

}
