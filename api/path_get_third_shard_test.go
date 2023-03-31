package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryadavDeqode/dq-vault/api/helpers"
	"github.com/ryadavDeqode/dq-vault/config"
	"github.com/ryadavDeqode/dq-vault/test/unit_test/mocks"
)

func TestPathGetThirdShard(t *testing.T) {

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

	res, err := b.pathGetThirdShard(context.Background(), &req, &framework.FieldData{})

	if err.Error() != tErr {
		t.Error("expected test error, received - ", res, err)
	}

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, nil).AnyTimes()
	mpdj := MPatchDecodeJSON(nil)

	res, err = b.pathGetThirdShard(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
	}

	mpjwt := MPatchVerifyJWTSignature(true, "")

	res, err = b.pathGetThirdShard(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
	}

	mpdj.Unpatch()
	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{IsRestoreInProgress: true, RestoreInitiationTimestamp: 2 * time.Now().Unix()})

	res, err = b.pathGetThirdShard(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
	}

	mpdj.Unpatch()
	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{IsRestoreInProgress: true})

	s = mocks.NewMockStorage(ctrl)

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, nil).AnyTimes()
	s.EXPECT().List(context.Background(), config.StorageBasePath).Return([]string{"test"}, nil).AnyTimes()
	s.EXPECT().Put(context.Background(), gomock.Any()).Return(errors.New(tErr))

	req = logical.Request{}

	req.Storage = s

	b = backend{}

	res, err = b.pathGetThirdShard(context.Background(), &req, &framework.FieldData{})

	if err == nil {
		t.Error(" error was expected, received - ", err, res)
	}

	s.EXPECT().Put(context.Background(), gomock.Any()).Return(nil)

	res, err = b.pathGetThirdShard(context.Background(), &req, &framework.FieldData{})

	if !res.Data["status"].(bool) {
		t.Error(" unexpected value of status,expected false, received - ", res)
	}

	mpget.Unpatch()
	mpdj.Unpatch()
	mpjwt.Unpatch()

}
