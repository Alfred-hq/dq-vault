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

func TestPathRemoveGuardian(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := mocks.NewMockStorage(ctrl)

	tErr := errors.New("test error")

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, tErr)
	s.EXPECT().List(context.Background(), config.StorageBasePath).Return([]string{"test"}, nil).AnyTimes()
	s.EXPECT().Put(context.Background(), gomock.Any()).Return(nil).AnyTimes()
	b := backend{}
	req := logical.Request{}

	req.Storage = s

	mpget := MPatchGet("test")

	res, err := b.pathRemoveGuardian(context.Background(), &req, &framework.FieldData{})

	if tErr.Error() != err.Error() {
		t.Error("expected test error, received - ", res, err)
	}

	mpdj := MPatchDecodeJSON(tErr)
	s.EXPECT().Get(context.Background(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, nil).AnyTimes()

	res, err = b.pathRemoveGuardian(context.Background(), &req, &framework.FieldData{})
	mpdj.Unpatch()

	if tErr.Error() != err.Error() {
		t.Error("expected test error, received - ", res, err)
	}

	mpdj.Unpatch()
	mpdj = MPatchDecodeJSON(nil)
	mpjwt := MPatchVerifyJWTSignature(false, tErr.Error())

	res, err = b.pathRemoveGuardian(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}

		if res.Data["remarks"] != tErr.Error() {
			t.Error("unexpected value of remarks, expected - ", tErr.Error(), "received - ", res)
		}
	}

	mpjwt.Unpatch()
	mpjwt = MPatchVerifyJWTSignature(true, tErr.Error())
	mpStringInSlice := MPatchStringInSlice(false)
	res, err = b.pathRemoveGuardian(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}

	}

	mpjwt.Unpatch()
	mpStringInSlice.Unpatch()
	mpjwt = MPatchVerifyJWTSignature(true, tErr.Error())
	mpStringInSlice = MPatchStringInSlice(true)
	mpnc := MPatchNewClient(nil)
	mpgetps := MPatchGetPubSub(tErr.Error(), nil)

	res, err = b.pathRemoveGuardian(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error("Expected no error, received - ", err)
	}

	mpjwt.Unpatch()
	mpStringInSlice.Unpatch()
	mpdj.Unpatch()

	mpjwt = MPatchVerifyJWTSignature(true, tErr.Error())
	mpStringInSlice = MPatchStringInSlice(true)
	mpdj = MPatchDecodeJSONOverrideStruct(
		helpers.UserDetails{
			UnverifiedGuardians:        []string{"test", "", ""},
			Guardians:                  []string{"", "", ""},
			GuardianIdentifiers:        []string{"", "", ""},
			GuardiansAddLinkInitiation: []int64{0, 0, 0},
		})

	res, err = b.pathRemoveGuardian(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error("Expected no error, received - ", err)
	} else if !res.Data["status"].(bool) {
		t.Error("Unexpected value of status, expected true, received - ", res)
	}

	mpdj.Unpatch()
	mpdj = MPatchDecodeJSONOverrideStruct(
		helpers.UserDetails{
			UnverifiedGuardians:        []string{"", "test", ""},
			Guardians:                  []string{"", "", ""},
			GuardianIdentifiers:        []string{"", "", ""},
			GuardiansAddLinkInitiation: []int64{0, 0, 0},
		})

	res, err = b.pathRemoveGuardian(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error("Expected no error, received - ", err)
	} else if !res.Data["status"].(bool) {
		t.Error("Unexpected value of status, expected true, received - ", res)
	}

	mpStorageJson := MPatchEntryJSON(tErr)

	res, err = b.pathRemoveGuardian(context.Background(), &req, &framework.FieldData{})

	if err == nil {
		t.Error("Expected error, received - ", res)
	}

	mpStorageJson.Unpatch()

	s = mocks.NewMockStorage(ctrl)

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, nil).AnyTimes()
	s.EXPECT().List(context.Background(), config.StorageBasePath).Return([]string{"test"}, nil).AnyTimes()
	s.EXPECT().Put(context.Background(), gomock.Any()).Return(tErr)
	b = backend{}
	req = logical.Request{}

	req.Storage = s

	res, err = b.pathRemoveGuardian(context.Background(), &req, &framework.FieldData{})

	if err == nil {
		t.Error("Expected error, received - ", res)
	}

	s.EXPECT().Put(context.Background(), gomock.Any()).Return(nil).AnyTimes()

	mpStorageJson.Unpatch()
	mpStorageEntryJson := MPatchEntryJSON(tErr)
	res, err = b.pathRemoveGuardian(context.Background(), &req, &framework.FieldData{})

	if err == nil {
		t.Error("Expected error, received - ", res)
	}

	mpStorageEntryJson.Unpatch()
	mpnc.Unpatch()

	mpnc = MPatchNewClient(tErr)

	res, err = b.pathRemoveGuardian(context.Background(), &req, &framework.FieldData{})

	if err == nil {
		t.Error("Expected error, received - ", res)
	}

	mpStorageEntryJson.Unpatch()
	mpStorageJson.Unpatch()
	mpget.Unpatch()
	mpdj.Unpatch()
	mpjwt.Unpatch()
	mpStringInSlice.Unpatch()
	mpnc.Unpatch()
	mpgetps.Unpatch()

}
