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

func TestVerifyGuardian(t *testing.T) {

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

	res, err := b.pathVerifyGuardian(context.Background(), &req, &framework.FieldData{})

	if err.Error() != tErr {
		t.Error("expected test error, received - ", res, err)
	}

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"").Return(&logical.StorageEntry{}, errors.New(tErr))
	mpdj := MPatchDecodeJSON(nil)
	mpnc := MPatchNewClient()

	res, err = b.pathVerifyGuardian(context.Background(), &req, &framework.FieldData{})

	if err.Error() != tErr {
		t.Error("expected test error, received - ", res, err)
	}

	mpSplit := MPatchSplitString([]string{"test"})

	res, err = b.pathVerifyGuardian(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
	}

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"").Return(&logical.StorageEntry{}, nil).AnyTimes()
	mpSplit.Unpatch()
	mpSplit = MPatchSplitString([]string{"", "test"})

	res, err = b.pathVerifyGuardian(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
	}
	mpdj.Unpatch()
	mpOverrideStruct := MPatchDecodeJSONOverrideStruct(helpers.UserDetails{Guardians: []string{"test"}})

	res, err = b.pathVerifyGuardian(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}

		if res.Data["remarks"] != "Guardian already added!" {
			t.Error(" unexpected value of remarks,expected \"Guardian already added!\", received - ", res.Data["remarks"])
		}

	}
	mpSplit.Unpatch()
	mpOverrideStruct.Unpatch()
	mpOverrideStruct = MPatchDecodeJSONOverrideStruct(
		helpers.UserDetails{
			Guardians:                  []string{"test"},
			UnverifiedGuardians:        []string{"test2"},
			GuardiansAddLinkInitiation: []int64{0, 0},
		})
	mpSplit = MPatchSplitString([]string{"", "test2"})

	res, err = b.pathVerifyGuardian(context.Background(), &req, &framework.FieldData{})
	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}

		if res.Data["remarks"] != "Link Expired!" {
			t.Error(" unexpected value of remarks,expected \"Link Expired!\", received - ", res.Data["remarks"])

		}
	}

	mpOverrideStruct.Unpatch()
	mpgetps := MPatchGetPubSub("test", nil)
	mpOverrideStruct = MPatchDecodeJSONOverrideStruct(
		helpers.UserDetails{
			Guardians:                  []string{"test"},
			UnverifiedGuardians:        []string{"test2"},
			GuardiansAddLinkInitiation: []int64{2 * time.Now().Unix(), 0},
			GuardianIdentifiers:        []string{"", ""},
		})

	res, err = b.pathVerifyGuardian(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if !res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected true, received - ", res)
		}
	}

	mpget.Unpatch()
	mpnc.Unpatch()
	mpgetps.Unpatch()
	mpOverrideStruct.Unpatch()
	mpSplit.Unpatch()

}
