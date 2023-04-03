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

func TestPathInitiateWalletRestoration(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := mocks.NewMockStorage(ctrl)

	tErr := "test error"
	s.EXPECT().Get(context.Background(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, errors.New(tErr))
	s.EXPECT().List(context.Background(), config.StorageBasePath).Return([]string{"test"}, nil).AnyTimes()
	s.EXPECT().Put(context.Background(), gomock.Any()).Return(nil).AnyTimes()
	b := backend{}
	req := logical.Request{}

	req.Storage = s

	mpget := MPatchGet("test")

	res, err := b.pathInitiateWalletRestoration(context.Background(), &req, &framework.FieldData{})

	if err.Error() != tErr {
		t.Error("expected test error, received - ", res, err)
	}

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, nil).AnyTimes()
	mpdj := MPatchDecodeJSON(errors.New(tErr))
	res, err = b.pathInitiateWalletRestoration(context.Background(), &req, &framework.FieldData{})

	if err.Error() != tErr {
		t.Error("expected test error, received - ", res, err)
	}

	mpdj.Unpatch()
	mpdj = MPatchDecodeJSON(nil)
	res, err = b.pathInitiateWalletRestoration(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected true, received - ", res)
		}
	}
	mpjwt := MPatchVerifyJWTSignature(false, tErr)

	res, err = b.pathInitiateWalletRestoration(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected true, received - ", res)
		}
		if res.Data["remarks"] != tErr {
			t.Error(" unexpected value of remarks,expected \"success\", received - ", res)
		}
	}

	mpjwt.Unpatch()
	mpjwt = MPatchVerifyJWTSignature(true, tErr)

	res, err = b.pathInitiateWalletRestoration(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if !res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected true, received - ", res)
		}
		if res.Data["remarks"] != "success" {
			t.Error(" unexpected value of remarks,expected \"success\", received - ", res)
		}
	}

	mpget.Unpatch()

	s = mocks.NewMockStorage(ctrl)
	req.Storage = s
	s.EXPECT().Get(context.Background(), config.StorageBasePath+"EMAIL").Return(&logical.StorageEntry{}, nil).AnyTimes()

	mpget = MPatchGet("EMAIL")
	mpnc := MPatchNewClient(errors.New(tErr))

	res, err = b.pathInitiateWalletRestoration(context.Background(), &req, &framework.FieldData{})

	if err.Error() != tErr {
		t.Error("expected test error, received - ", res, err)
	}

	mpget.Unpatch()
	mpnc.Unpatch()

	mpget = MPatchGet("MOBILE")
	mpnc = MPatchNewClient(errors.New(tErr))

	res, err = b.pathInitiateWalletRestoration(context.Background(), &req, &framework.FieldData{})

	if err.Error() != tErr {
		t.Error("expected test error, received - ", res, err)
	}

	mpnc.Unpatch()

	mpdj.Unpatch()
	mpget.Unpatch()
	mpjwt.Unpatch()
}
