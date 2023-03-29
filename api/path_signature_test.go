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

func TestPathSignature(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tErr := "test error"

	mpget := MPatchGet("test")

	s := mocks.NewMockStorage(ctrl)
	b := backend{}
	req := logical.Request{}
	req.Storage = s

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, errors.New(tErr))
	s.EXPECT().List(context.Background(), config.StorageBasePath).Return([]string{"test"}, nil).AnyTimes()
	s.EXPECT().Put(context.Background(), gomock.Any()).Return(nil).AnyTimes()

	res, err := b.pathSignature(context.Background(), &req, &framework.FieldData{})

	if err == nil {
		t.Error("expected Error, received", res)
	} else if err.Error() != tErr {
		t.Error("unexpected Error, expected - ", tErr, "received", err.Error())
	}

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, nil).AnyTimes()

	mpdj := MPatchDecodeJSON(errors.New(tErr))

	res, err = b.pathSignature(context.Background(), &req, &framework.FieldData{})

	if err == nil {
		t.Error("expected Error, received", res)
	} else if err.Error() != tErr {
		t.Error("unexpected Error, expected - ", tErr, "received", err.Error())
	}

	mpdj.Unpatch()

	mpdj = MPatchDecodeJSON(nil)
	mpdpk := MPatchDerivePrivateKey("", errors.New(tErr))

	res, err = b.pathSignature(context.Background(), &req, &framework.FieldData{})

	if err == nil {
		t.Error("expected Error, received", res)
	} else if err.Error() != tErr {
		t.Error("unexpected Error, expected - ", tErr, "received", err.Error())
	}

	mpdpk.Unpatch()
	mpDerivePrivateKey := MPatchDerivePrivateKey("", nil)
	mpcst := MPatchCreateSignedTransaction("", errors.New(tErr))

	res, err = b.pathSignature(context.Background(), &req, &framework.FieldData{})

	if err == nil {
		t.Error("expected Error, received", res)
	} else if err.Error() != tErr {
		t.Error("unexpected Error, expected - ", tErr, "received", err.Error())
	}

	mpcst.Unpatch()

	mpTxn := MPatchCreateSignedTransaction(tErr, nil)

	res, err = b.pathSignature(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["signature"] != tErr {
			t.Error(" unexpected value of status,expected ", tErr, "received", res)
		}
	}

	mpTxn.Unpatch()
	mpDerivePrivateKey.Unpatch()
	mpdj.Unpatch()
	mpdpk.Unpatch()
	mpget.Unpatch()
}
