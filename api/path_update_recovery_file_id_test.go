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

func TestPathUpdateRecoveryFileId(t *testing.T) {

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

	MPatchGet("")

	res, err := b.pathUpdateRecoveryFileId(context.Background(), &req, &framework.FieldData{})

	if err.Error() != tErr {
		t.Error("expected test error, received - ", res, err)
	}

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"").Return(&logical.StorageEntry{}, nil).AnyTimes()
	mpdj := MPatchDecodeJSON(errors.New(tErr))
	MPatchNewClient()

	res, err = b.pathUpdateRecoveryFileId(context.Background(), &req, &framework.FieldData{})

	if err.Error() != tErr {
		t.Error("expected test error, received - ", res, err)
	}

	mpdj.Unpatch()

	mpdj = MPatchDecodeJSON(nil)
	MPatchVerifyJWTSignature(false, tErr)

	res, err = b.pathUpdateRecoveryFileId(context.Background(), &req, &framework.FieldData{})

	if err.Error() != tErr {
		t.Error("expected test error, received - ", res, err)
	}
	
	

	// mpdj = MPatchDecodeJSONOverrideStruct(
	// 	helpers.UserDetails{
	// 		Guardians:                  []string{"test"},
	// 		UnverifiedGuardians:        []string{"test2"},
	// 		GuardiansAddLinkInitiation: []int64{0, 0},
	// 	})

	// res, err = b.pathUpdateRecoveryFileId(context.Background(), &req, &framework.FieldData{})

	// t.Error(res, err)

	// if err != nil {
	// 	t.Error(" error wasn't expected, received - ", err)
	// } else {
	// 	if res.Data["status"].(bool) {
	// 		t.Error(" unexpected value of status,expected false, received - ", res)
	// 	}
	// }

	





}
