package api

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryadavDeqode/dq-vault/test/unit_test/mocks"
)

func TestPathNewUser(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := mocks.NewMockStorage(ctrl)

	tErr := "test error"

	s.EXPECT().Put(context.Background(), gomock.Any()).Return(nil)
	b := backend{}
	req := logical.Request{}

	req.Storage = s

	mpget := MPatchGet("test")

	res, err := b.pathNewUser(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
	}

	mpjwt := MPatchVerifyJWTSignature(true, tErr)
	s.EXPECT().Put(context.Background(), gomock.Any()).Return(nil)

	res, err = b.pathNewUser(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if !res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected true, received - ", res)
		}
	}

	s.EXPECT().Put(context.Background(), gomock.Any()).Return(errors.New(tErr)).AnyTimes()

	res, err = b.pathNewUser(context.Background(), &req, &framework.FieldData{})

	if err == nil {
		t.Error(res, err)
	}

	mpget.Unpatch()
	mpjwt.Unpatch()

}
