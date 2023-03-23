package api

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryadavDeqode/dq-vault/config"
	"github.com/ryadavDeqode/dq-vault/test/unit_test/mocks"
)

func TestPathAddMFASource(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := mocks.NewMockStorage(ctrl)

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, nil).AnyTimes()

	req := logical.Request{}

	req.Storage = s

	d := framework.FieldData{}

	MPatchGet("test")

	b := backend{}
	res, err := b.pathAddMFASource(context.Background(), &req, &d)

	// pGet.Unpatch()

	if err == nil {
		t.Error("expected error, received - ", res)
	}

	MPatchDecodeJSON(nil)

	res, err = b.pathAddMFASource(context.Background(), &req, &d)

	if err != nil {
		t.Error("expected no error, received - ", err, res)
	}

	if res.Data["status"] != false {
		t.Error("unexpected value of status, received - ", err, res)
	}

	mJWTSignature:= MPatchVerifyJWTSignature(false, "test")

	res, err = b.pathAddMFASource(context.Background(), &req, &d)

	if err != nil {
		t.Error("expected no error, received - ", err, res)
	}

	if res.Data["remarks"] != "test" {
		t.Error("unexpected value of remarks, received - ", err, res)
	}

	mJWTSignature.Unpatch()
	MPatchVerifyJWTSignature(true, "test")
	MPatchNewClient()
	s.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil)

	res, err = b.pathAddMFASource(context.Background(), &req, &d)

	if err != nil {

		t.Error("expected no error, received - ", err, res)
	}

	if !res.Data["status"].(bool) {
		t.Error("unexpected value of status, expected true, received - ", res)
	}
}
