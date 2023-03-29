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

func TestPathCancelWalletRestoration(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := mocks.NewMockStorage(ctrl)

	tErr := "test error"
	s.EXPECT().Get(context.Background(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, errors.New(tErr))
	s.EXPECT().List(context.Background(), config.StorageBasePath).Return([]string{"test"}, nil).AnyTimes()
	s.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	b := backend{}
	req := logical.Request{}

	req.Storage = s

	mpget := MPatchGet("test")

	res, err := b.pathCancelWalletRestoration(context.Background(), &req, &framework.FieldData{})

	// if t.
	if err == nil {
		t.Error("expected error, received", res)
	} else if err.Error() != tErr {

		t.Error("unexpected error, expected - "+tErr+", received - ", res)
	}

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, nil).AnyTimes()
	mpdj := MPatchDecodeJSON(errors.New(tErr))
	res, err = b.pathCancelWalletRestoration(context.Background(), &req, &framework.FieldData{})
	mpdj.Unpatch()

	if err == nil {
		t.Error("expected error, received", res)
	} else if err.Error() != tErr {

		t.Error("unexpected error, expected - "+tErr+", received - ", res)
	}

	mpdj = MPatchDecodeJSON(nil)

	res, err = b.pathCancelWalletRestoration(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error("Expected error to be nil, received - ", err)
	} else if res.Data["status"].(bool) {
		t.Error("Unexpected value of status, expected false, received , ", res)
	}

	mpjwt := MPatchVerifyJWTSignature(true, tErr)

	res, err = b.pathCancelWalletRestoration(context.Background(), &req, &framework.FieldData{})


	if err != nil {
		t.Error("Expected error to be nil, received - ", err)
	} else if !res.Data["status"].(bool) {
		t.Error("Unexpected value of status, expected true, received , ", res)
	}

	mpdj.Unpatch()
	mpjwt.Unpatch()
	mpget.Unpatch()
}
