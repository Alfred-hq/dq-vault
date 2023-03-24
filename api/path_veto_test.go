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

func TestPathVeto(t *testing.T) {

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

	MPatchGet("test")

	res, err := b.pathVeto(context.Background(), &req, &framework.FieldData{})

	if err.Error() != tErr {
		t.Error("expected test error, received - ", res, err)
	}

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, nil).AnyTimes()
	mpdj := MPatchDecodeJSON(nil)
	MPatchNewClient()

	res, err = b.pathVeto(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
	}

	mpdj.Unpatch()
	mpdj = MPatchDecodeJSONOverrideStruct(
		helpers.UserDetails{
			Guardians:                  []string{"test"},
			UnverifiedGuardians:        []string{"test2"},
			GuardiansAddLinkInitiation: []int64{2 * time.Now().Unix(), 0},
			GuardianIdentifiers:        []string{"test", ""},
			IsRestoreInProgress:        false,
		})

	MPatchVerifyJWTSignature(true, "")

	res, err = b.pathVeto(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}

		if res.Data["remarks"] != "Either wallet restored or vetoed by other guardian" {
			t.Error(" unexpected value of remarks,expected \"Link Expired!\", received - ", res.Data["remarks"])
		}
	}

	mpdj.Unpatch()
	mpdj = MPatchDecodeJSONOverrideStruct(
		helpers.UserDetails{
			Guardians:                  []string{"test"},
			UnverifiedGuardians:        []string{"test2"},
			GuardiansAddLinkInitiation: []int64{2 * time.Now().Unix(), 0},
			GuardianIdentifiers:        []string{"test", ""},
			IsRestoreInProgress:        true,
			RestoreInitiationTimestamp: 0,
		})

	res, err = b.pathVeto(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}

		if res.Data["remarks"] != "wallet already restored" {
			t.Error(" unexpected value of remarks,expected \"wallet already restored!\", received - ", res.Data["remarks"])
		}
	}

	mpdj.Unpatch()
	mpGetPubSub := MPatchGetPubSub(tErr, errors.New(tErr))

	mpdj = MPatchDecodeJSONOverrideStruct(
		helpers.UserDetails{
			Guardians:                  []string{"test"},
			UnverifiedGuardians:        []string{"test2"},
			GuardiansAddLinkInitiation: []int64{2 * time.Now().Unix(), 2 * time.Now().Unix()},
			GuardianIdentifiers:        []string{"test", ""},
			IsRestoreInProgress:        true,
			RestoreInitiationTimestamp: 2 * time.Now().Unix(),
		})

	res, err = b.pathVeto(context.Background(), &req, &framework.FieldData{})

	if err == nil {
		t.Error("expected Error, received", res)
	} else if err.Error() != tErr {
		t.Error("unexpected Error, expected - ", tErr, "received", err.Error())
	}

	mpGetPubSub.Unpatch()

	mpGetPubSub = MPatchGetPubSub(tErr, nil)

	res, err = b.pathVeto(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if !res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected true, received - ", res)
		}
	}

}
