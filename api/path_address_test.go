package api

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryadavDeqode/dq-vault/config"
	"github.com/ryadavDeqode/dq-vault/test/unit_test/mocks"
)

func TestPathAddress(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := mocks.NewMockStorage(ctrl)
	b := backend{}
	req := logical.Request{}

	tErr := "test error"

	MPatchGet("test")

	s.EXPECT().Get(gomock.Any(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, errors.New(tErr))
	s.EXPECT().List(gomock.Any(), config.StorageBasePath).Return([]string{"test"}, nil).AnyTimes()
	req.Storage = s

	res, err := b.pathAddress(context.Background(), &req, &framework.FieldData{})

	if err == nil {
		t.Error("expected Error, received", res)
	} else if err.Error() != tErr {
		t.Error("unexpected Error, expected - ", tErr, "received", err.Error())
	}

	s.EXPECT().Get(gomock.Any(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, nil).AnyTimes()

	mpdj := MPatchDecodeJSON(errors.New(tErr))
	res, err = b.pathAddress(context.Background(), &req, &framework.FieldData{})

	if err == nil {
		t.Error("expected Error, received", res)
	} else if err.Error() != tErr {
		t.Error("unexpected Error, expected - ", tErr, "received", err.Error())
	}

	mpdj.Unpatch()

	MPatchDecodeJSON(nil)
	mpdPrivateKey := MPatchDerivePrivateKey(tErr, nil)
	mpdPublicKey := MPatchDerivePublicKey(tErr, nil)
	mpdDeriveAddress := MPatchDeriveAddress(tErr, nil)

	res, err = b.pathAddress(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error("expected no error", "received", err.Error())
	} else if len(res.Data) != 3 {
		t.Error("not enough field in map", "expected 3", "received", len(res.Data))
	} else if res.Data["uuid"] != "test" {
		t.Error("unexpected value of field uuid", "expected ", "test", "received", res.Data["uuid"])
	}

	mpdPublicKey.Unpatch()
	mpdPrivateKey.Unpatch()
	mpdDeriveAddress.Unpatch()

}
