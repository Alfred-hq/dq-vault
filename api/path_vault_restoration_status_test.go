package api

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryadavDeqode/dq-vault/api/helpers"
	"github.com/ryadavDeqode/dq-vault/config"
	"github.com/ryadavDeqode/dq-vault/test/unit_test/mocks"
)

func TestPathGetUserVaultRestorationStatus(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := mocks.NewMockStorage(ctrl)

	tErr := "test error"

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, errors.New(tErr))

	req := logical.Request{}

	req.Storage = s

	d := framework.FieldData{}

	mpget := MPatchGet("test")

	b := backend{}
	res, err := b.pathGetUserVaultRestorationStatus(context.Background(), &req, &d)

	if err == nil {
		t.Error("expected error, received - ", res)
	} else if err.Error() != tErr {
		t.Error("unexpected error message, expected,", tErr, "received - ", res)

	}

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, nil).AnyTimes()

	mpdj := MPatchDecodeJSON(errors.New(tErr))

	res, err = b.pathGetUserVaultRestorationStatus(context.Background(), &req, &d)

	if err == nil {
		t.Error("expected error, received - ", res)
	} else if err.Error() != tErr {
		t.Error("unexpected error message, expected,", tErr, "received - ", res)

	}

	mpdj.Unpatch()
	mpdj = MPatchDecodeJSON(nil)

	mpjwt := MPatchVerifyJWTSignature(false, tErr)

	res, err = b.pathGetUserVaultRestorationStatus(context.Background(), &req, &d)

	if err != nil {
		t.Error("expected no errors, received - ", err)
	} else if res.Data["status"].(bool) {
		t.Error("unexpected data , expected,", "status:false", "received - ", res)
	}

	mpjwt.Unpatch()
	mpjwt = MPatchVerifyJWTSignature(true, tErr)
	mpatoi := MPatchAtoi(nil)
	mpdj.Unpatch()
	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{Guardians: []string{"test", "test", "test"}, UnverifiedGuardians: []string{"", "", ""}})
	res, err = b.pathGetUserVaultRestorationStatus(context.Background(), &req, &d)

	if err != nil {
		t.Error("expected no errors, received - ", err)
	} else if !res.Data["status"].(bool) {
		t.Error("unexpected data , expected,", "status:true", "received - ", res)
	}

	mpjwt.Unpatch()
	mpatoi.Unpatch()
	mpdj.Unpatch()
	mpget.Unpatch()


	
}
