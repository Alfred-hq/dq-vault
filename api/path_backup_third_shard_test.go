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

func TestPathBackupThirdShard(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := mocks.NewMockStorage(ctrl)

	tErr := "test error"
	s.EXPECT().Get(context.Background(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, errors.New(tErr))
	s.EXPECT().List(context.Background(), config.StorageBasePath).Return([]string{"test"}, nil).AnyTimes()
	s.EXPECT().Put(context.Background(), gomock.Any()).Return(nil)
	b := backend{}
	req := logical.Request{}

	req.Storage = s

	MPatchGet("test")

	res, err := b.pathBackupThirdShard(context.Background(), &req, &framework.FieldData{})

	if err.Error() != tErr {
		t.Error("expected test error, received - ", res, err)
	}

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, nil).AnyTimes()
	MPatchDecodeJSON(nil)

	res, err = b.pathBackupThirdShard(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", err)
		}
	}

	tr := "test_remark"

	mpjwt, _ := MPatchVerifyJWTSignature(false, tr)

	res, err = b.pathBackupThirdShard(context.Background(), &req, &framework.FieldData{})
	mpjwt.Unpatch()

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
		if res.Data["remarks"] != tr {

			t.Error(" unexpected value of remarks,expected \"test_remarks\", received - ", res)
		}
	}

	MPatchVerifyJWTSignature(true, tr)

	res, err = b.pathBackupThirdShard(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if !res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected true, received - ", res)
		}
		if res.Data["remarks"] != "success!" {
			t.Error(" unexpected value of remarks,expected \"success\", received - ", res)
		}
	}



}
