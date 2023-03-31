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

func TestPathAddMFASource(t *testing.T) {
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
	res, err := b.pathAddMFASource(context.Background(), &req, &d)

	if err == nil {
		t.Error("expected error, received - ", res)
	}

	s.EXPECT().Get(context.Background(), gomock.Any()).Return(&logical.StorageEntry{}, nil).AnyTimes()

	mpdj := MPatchDecodeJSON(errors.New(tErr))

	res, err = b.pathAddMFASource(context.Background(), &req, &d)
	if err == nil {
		t.Error("expected error, received - ", res)
	}
	mpdj.Unpatch()
	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{IsRestoreInProgress: true})

	res, err = b.pathAddMFASource(context.Background(), &req, &d)

	if err != nil {
		t.Error("expected no error, received - ", err, res)
	} else if res.Data["status"].(bool) {
		t.Error("unexpected value", "Expected false - ", res.Data["status"])
	}

	mpdj.Unpatch()
	mpdj = MPatchDecodeJSON(nil)

	res, err = b.pathAddMFASource(context.Background(), &req, &d)

	if err != nil {
		t.Error("expected no error, received - ", err, res)
	}

	if res.Data["status"] != false {
		t.Error("unexpected value of status, received - ", err, res)
	}

	mJWTSignature := MPatchVerifyJWTSignature(false, "test")

	res, err = b.pathAddMFASource(context.Background(), &req, &d)

	if err != nil {
		t.Error("expected no error, received - ", err, res)
	}

	if res.Data["remarks"] != "test" {
		t.Error("unexpected value of remarks, received - ", err, res)
	}

	mJWTSignature.Unpatch()
	mJWTSignature = MPatchVerifyJWTSignature(true, "test")
	mpnc := MPatchNewClient(nil)
	s.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil)

	res, err = b.pathAddMFASource(context.Background(), &req, &d)

	if err != nil {

		t.Error("expected no error, received - ", err, res)
	}

	if !res.Data["status"].(bool) {
		t.Error("unexpected value of status, expected true, received - ", res)
	}

	mpget.Unpatch()

	mpget = MPatchGet("userEmail")

	mpnc.Unpatch()
	mpnc = MPatchNewClient(errors.New(tErr))

	res, err = b.pathAddMFASource(context.Background(), &req, &d)

	if err == nil && err.Error() != tErr {
		t.Error("unexpected error", "expected", tErr, "received - ", err)
	}

	mpnc.Unpatch()
	mpnc = MPatchNewClient(nil)

	mppubsub := MPatchGetPubSub(tErr, errors.New(tErr))
	res, err = b.pathAddMFASource(context.Background(), &req, &d)
	if err == nil && err.Error() != tErr {
		t.Error("unexpected error", "expected", tErr, "received - ", err)
	}

	mppubsub.Unpatch()
	mppubsub = MPatchGetPubSub(tErr, nil)
	s.EXPECT().Put(gomock.Any(), gomock.Any()).Return(errors.New(tErr))

	res, err = b.pathAddMFASource(context.Background(), &req, &d)
	if err == nil && err.Error() != tErr {
		t.Error("unexpected error", "expected", tErr, "received - ", err)
	}

	s.EXPECT().Put(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	mpget.Unpatch()

	mpget = MPatchGet("guardianEmail")
	mpatoi := MPatchAtoi(errors.New(tErr))

	res, err = b.pathAddMFASource(context.Background(), &req, &d)

	if err == nil && err.Error() != tErr {
		t.Error("unexpected error", "expected", tErr, "received - ", err)
	}

	mpatoi.Unpatch()
	mpatoi = MPatchAtoi(nil)
	mpdj.Unpatch()
	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{UserEmail: "guardianEmail"})
	res, err = b.pathAddMFASource(context.Background(), &req, &d)

	if err != nil {
		t.Error("expected no error, received - ", err, res)
	} else if res.Data["status"].(bool) {
		t.Error("unexpected value", "Expected false - ", res.Data["status"])
	}

	mpdj.Unpatch()
	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{Guardians: []string{"guardianEmail"}})
	res, err = b.pathAddMFASource(context.Background(), &req, &d)
	if err != nil {
		t.Error("expected no error, received - ", err, res)
	} else if res.Data["status"].(bool) {
		t.Error("unexpected value", "Expected false - ", res.Data["status"])
	}

	mpdj.Unpatch()
	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{UnverifiedGuardians: []string{""}, GuardiansAddLinkInitiation: []int64{0}})

	res, err = b.pathAddMFASource(context.Background(), &req, &d)

	if !res.Data["status"].(bool) {
		t.Error("unexpected value of status, expected true, received - ", res)
	}

	mpget.Unpatch()
	mpget = MPatchGet("userMobileNumber")

	res, err = b.pathAddMFASource(context.Background(), &req, &d)
	if !res.Data["status"].(bool) {
		t.Error("unexpected value of status, expected true, received - ", res)
	}

	mpget.Unpatch()

	mpatoi.Unpatch()
	mppubsub.Unpatch()
	mJWTSignature.Unpatch()
	mpnc.Unpatch()
	mpdj.Unpatch()
	mpget.Unpatch()
}
