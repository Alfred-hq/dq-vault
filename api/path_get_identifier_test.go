package api

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryadavDeqode/dq-vault/config"
	"github.com/ryadavDeqode/dq-vault/test/unit_test/mocks"
)

func TestPathGetIdentifier(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := mocks.NewMockStorage(ctrl)

	tErr := "test error"

	s.EXPECT().Get(context.Background(), config.StorageBasePath+ base64.StdEncoding.EncodeToString([]byte("test"))).Return(&logical.StorageEntry{}, errors.New(tErr))
	s.EXPECT().List(context.Background(), config.StorageBasePath).Return([]string{"test"}, nil).AnyTimes()
	s.EXPECT().Put(context.Background(), gomock.Any()).Return(nil).AnyTimes()
	b := backend{}
	req := logical.Request{}

	req.Storage = s

	mpGet := MPatchGet("test")


	res, err := b.pathGetIdentifier(context.Background(), &req, &framework.FieldData{})


	if err.Error() != tErr {
		t.Error("expected test error, received - ", res, err)
	}

	mpdj := MPatchDecodeJSON(nil)
	s.EXPECT().Get(context.Background(), config.StorageBasePath+ base64.StdEncoding.EncodeToString([]byte("test"))).Return(&logical.StorageEntry{}, nil).AnyTimes()

	res, err = b.pathGetIdentifier(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
	}

	mpJWT := MPatchVerifyJWTSignature(true, "")

	res, err = b.pathGetIdentifier(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if !res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected true, received - ", res)
		}
	}

	mpGet.Unpatch()
	mpJWT.Unpatch()
	mpdj.Unpatch()
	
}
