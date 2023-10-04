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

func TestPathGuardians(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	b := backend{}

	tErr := "test error"

	req := logical.Request{}
	d := framework.FieldData{}

	mpget := MPatchGet("test")

	pathGs, err := b.pathGuardians(context.Background(), &req, &d)

	mpget.Unpatch()

	if err != nil {
		t.Error("error wasn't expected", err)
	} else if pathGs.Data["remarks"] != "return proper quest" {
		t.Error("not the response expected!", pathGs)
	}

	mpget = MPatchGet("GET_GUARDIANS")

	s := mocks.NewMockStorage(ctrl)

	req.Storage = s

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"GET_GUARDIANS").Return(&logical.StorageEntry{}, errors.New(tErr))

	_, err = b.pathGuardians(context.Background(), &req, &d)

	if err == nil {
		t.Error("error was expected", err)
	} else if err.Error() != tErr {
		t.Error("expected error to be ", tErr, "received", err.Error())

	}

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"GET_GUARDIANS").Return(&logical.StorageEntry{}, nil).AnyTimes()

	_, err = b.pathGuardians(context.Background(), &req, &d)

	if err == nil {
		t.Error("error was expected", err)
	}

	mpdj := MPatchDecodeJSON(errors.New(tErr))

	_, err = b.pathGuardians(context.Background(), &req, &d)

	if err == nil {
		t.Error("error was expected", err)
	} else if err.Error() != tErr {
		t.Error("expected error to be ", tErr, "received", err.Error())

	}

	mpdj.Unpatch()

	mpdj = MPatchDecodeJSON(nil)
	pathGs, err = b.pathGuardians(context.Background(), &req, &d)

	if err != nil {
		t.Error("no error was expected", pathGs, err)
	}
	testRemark := "test_remark"
	mpjwt := MPatchVerifyJWTSignature(false, testRemark)

	pathGs, err = b.pathGuardians(context.Background(), &req, &d)

	mpjwt.Unpatch()

	if err != nil {
		t.Error("no error was expected", pathGs, err)
	}
	if pathGs.Data["remarks"] != testRemark {
		t.Error("unexpected return value!", pathGs)
	}

	mpjwt = MPatchVerifyJWTSignature(true, testRemark)

	pathGs, err = b.pathGuardians(context.Background(), &req, &d)

	if err != nil {
		t.Error("no error was expected", pathGs, err)
	}

	if pathGs.Data["remarks"] != "success" {
		t.Error("unexpected remarks value, expected success, received - ", pathGs)
	}

	if pathGs.Data["status"] != true {
		t.Error("unexpected status value, expected true, received - ", pathGs)
	}

	mpdj.Unpatch()
	mpget.Unpatch()
	mpjwt.Unpatch()
}
