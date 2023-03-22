package api

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryadavDeqode/dq-vault/config"
	"github.com/ryadavDeqode/dq-vault/test/unit_test/mocks"
)

func TestPathGuardians(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	b := backend{}

	req := logical.Request{}
	d := framework.FieldData{}

	p, _ := MPatchGet("test")

	pathGs, err := b.pathGuardians(context.Background(), &req, &d)

	p.Unpatch()

	if pathGs.Data["remarks"] != "return proper quest" {
		t.Error("not the response expected!", pathGs)
	}

	if err != nil {
		t.Error("error wasn't expected", err)
	}

	MPatchGet("GET_GUARDIANS")

	s := mocks.NewMockStorage(ctrl)

	req.Storage = s

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"GET_GUARDIANS").Return(&logical.StorageEntry{}, nil).MinTimes(0)
	_, err = b.pathGuardians(context.Background(), &req, &d)

	if err == nil {
		t.Error("error was expected", err)
	}

	MPatchDecodeJSON(nil)

	pathGs, err = b.pathGuardians(context.Background(), &req, &d)

	if err != nil {
		t.Error("no error was expected", pathGs, err)
	}
	testRemark := "test_remark"
	mJWT,_ := MPatchVerifyJWTSignature(false, testRemark)

	pathGs, err = b.pathGuardians(context.Background(), &req, &d)

	mJWT.Unpatch()

	if err != nil {
		t.Error("no error was expected", pathGs, err)
	}
	if pathGs.Data["remarks"] != testRemark {
		t.Error("unexpected return value!", pathGs)
	}


	MPatchVerifyJWTSignature(true, testRemark)

	pathGs, err = b.pathGuardians(context.Background(), &req, &d)

	if err != nil {
		t.Error("no error was expected", pathGs, err)
	}

	if pathGs.Data["remarks"] != "success"{
		t.Error("unexpected remarks value, expected success, received - ", pathGs)
	}

	if pathGs.Data["status"] != true {
		t.Error("unexpected status value, expected true, received - ", pathGs)
	}
}
