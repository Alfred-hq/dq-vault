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

func TestPathSign(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := mocks.NewMockStorage(ctrl)

	tErr := "test error"
	s.EXPECT().Get(context.Background(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, errors.New(tErr))
	s.EXPECT().List(context.Background(), config.StorageBasePath).Return([]string{"test"}, nil).AnyTimes()
	b := backend{}
	req := logical.Request{}

	req.Storage = s

	mpget := MPatchGet("test")

	res, err := b.pathSign(context.Background(), &req, &framework.FieldData{})

	if err.Error() != tErr {
		t.Error("expected test error, received - ", res, err)
	}

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, nil).AnyTimes()
	req.Storage = s
	mpdj := MPatchDecodeJSON(errors.New(tErr))
	res, err = b.pathSign(context.Background(), &req, &framework.FieldData{})

	if err == nil {
		t.Error("expected Error, received", res)
	} else if err.Error() != tErr {
		t.Error("unexpected Error, expected - ", tErr, "received", err.Error())
	}

	mpdj.Unpatch()

	mpdj = MPatchDecodeJSON(nil)
	mpdpk := MPatchDerivePrivateKey("", errors.New(tErr))

	res, err = b.pathSign(context.Background(), &req, &framework.FieldData{})

	if err == nil {
		t.Error("expected Error, received", res)
	} else if err.Error() != tErr {
		t.Error("unexpected Error, expected - ", tErr, "received", err.Error())
	}
	mpdpk.Unpatch()

	mpdpk = MPatchDerivePrivateKey(tErr, nil)
	mpsign := MPatchCreateSignature(tErr, nil)

	res, err = b.pathSign(context.Background(), &req, &framework.FieldData{})
	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["signature"] != tErr {
			t.Error(" unexpected value of status,expected ", tErr, "received", res)
		}
	}

	mpValidateFields := MPatchValidateFields(errors.New(tErr))
	res, err = b.pathSign(context.Background(), &req, &framework.FieldData{})

	if err == nil {
		t.Error("expected Error, received", res)
	}

	mpValidateFields.Unpatch()
	
	mpdj.Unpatch()
	mpdpk.Unpatch()
	mpget.Unpatch()
	mpsign.Unpatch()
}
