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

func TestPathGetUserVaultStatus(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := mocks.NewMockStorage(ctrl)

	tErr := "test error"
	s.EXPECT().Get(context.Background(), config.StorageBasePath+"").Return(&logical.StorageEntry{}, errors.New(tErr))
	s.EXPECT().List(context.Background(), config.StorageBasePath).Return([]string{"test"}, nil).AnyTimes()
	s.EXPECT().Put(context.Background(), gomock.Any()).Return(nil).AnyTimes()
	b := backend{}
	req := logical.Request{}

	req.Storage = s

	mpget := MPatchGet("")

	res, err := b.pathGetUserVaultStatus(context.Background(), &req, &framework.FieldData{})

	if err.Error() != tErr {
		t.Error("expected test error, received - ", res, err)
	}

	mpDecodeJson := MPatchDecodeJSON(errors.New(tErr))

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"").Return(&logical.StorageEntry{}, nil).AnyTimes()

	res, err = b.pathGetUserVaultStatus(context.Background(), &req, &framework.FieldData{})

	if err.Error() != tErr {
		t.Error("expected test error, received - ", res, err)
	}

	mpDecodeJson.Unpatch()
	mpDecodeJson = MPatchDecodeJSON(nil)
	mpJWT := MPatchVerifyJWTSignature(false, tErr)

	res, err = b.pathGetUserVaultStatus(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}

		if res.Data["remarks"] != tErr {
			t.Error(" unexpected value of remarks,expected -", tErr, "received - ", res.Data["remarks"])
		}
	}

	mpJWT.Unpatch()
	mpDecodeJson.Unpatch()
	mpJWT = MPatchVerifyJWTSignature(true, tErr)
	mpdjOverride := MPatchDecodeJSONOverrideStruct(helpers.UserDetails{Guardians: []string{"test", "test1", "test2"}, UnverifiedGuardians: []string{"test", "test1", "test2"}})

	res, err = b.pathGetUserVaultStatus(context.Background(), &req, &framework.FieldData{})


	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if !res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected true, received - ", res)
		}
	}

	mpget.Unpatch()
	mpJWT.Unpatch()
	mpdjOverride.Unpatch()
}
