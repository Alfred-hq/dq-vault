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

func TestPathSubmitOtp(t *testing.T) {

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

	res, err := b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})

	if err.Error() != tErr {
		t.Error("expected test error, received - ", res, err)
	}

	mpnc := MPatchNewClient(errors.New(tErr))
	s.EXPECT().Get(context.Background(), gomock.Any()).Return(&logical.StorageEntry{}, nil).AnyTimes()

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})

	if err.Error() != tErr {
		t.Error("expected test error, received - ", res, err)
	}

	mpnc.Unpatch()
	mpnc = MPatchNewClient(nil)
	mpdj := MPatchDecodeJSON(errors.New(tErr))

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})

	if err.Error() != tErr {
		t.Error("expected test error, received - ", res, err)
	}

	mpdj.Unpatch()
	mpdj = MPatchDecodeJSON(nil)

	mpAtoi := MPatchAtoi(errors.New(tErr))

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})

	if err.Error() != tErr {
		t.Error("expected test error, received - ", res, err)
	}

	mpAtoi.Unpatch()
	mpAtoi = MPatchAtoi(nil)

	mpget.Unpatch()

	// purpose 0
	purpose := helpers.PurposeType[0]
	mpget = MPatchGet(purpose)
	mpjwt := MPatchVerifyJWTSignature(false, tErr)

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})
	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
	}

	mpjwt.Unpatch()
	mpdj.Unpatch()
	mpjwt = MPatchVerifyJWTSignature(true, tErr)
	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{PrimaryEmailVerificationOTP: tErr})

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})
	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
		if res.Data["remarks"] != "OTP DID NOT MATCH" {
			t.Error("unexpected value of remarks -,", "expected- ", "OTP DID NOT MATCH", " received - ", res)
		}
	}

	mpdj.Unpatch()
	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{PrimaryEmailVerificationOTP: purpose})

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
		if res.Data["remarks"] != "OTP EXPIRED" {
			t.Error("unexpected value of remarks -,", "expected- ", "OTP EXPIRED", " received - ", res)
		}
	}

	mpdj.Unpatch()
	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{PrimaryEmailOTPGenerateTimestamp: 2 * time.Now().Unix(), PrimaryEmailVerificationOTP: purpose})

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if !res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected true, received - ", res)
		}
	}

	// purpose 1

	mpdj.Unpatch()
	mpget.Unpatch()
	mpjwt.Unpatch()

	purpose = helpers.PurposeType[1]
	mpget = MPatchGet(purpose)
	mpjwt = MPatchVerifyJWTSignature(false, tErr)
	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{PrimaryEmailVerificationOTP: tErr})

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})
	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
	}

	mpjwt.Unpatch()
	mpjwt = MPatchVerifyJWTSignature(true, tErr)

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})
	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
		if res.Data["remarks"] != "OTP DID NOT MATCH" {
			t.Error("unexpected value of remarks -,", "expected- ", "OTP DID NOT MATCH", " received - ", res)
		}
	}

	mpdj.Unpatch()

	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{MobileVerificationOTP: purpose})

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
		if res.Data["remarks"] != "OTP EXPIRED" {
			t.Error("unexpected value of remarks -,", "expected- ", "OTP EXPIRED", " received - ", res)
		}
	}

	mpdj.Unpatch()
	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{MobileOTPGenerateTimestamp: 2 * time.Now().Unix(), MobileVerificationOTP: purpose})

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if !res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected true, received - ", res)
		}
	}

	//  purpose 2

	mpdj.Unpatch()
	mpget.Unpatch()
	mpjwt.Unpatch()

	purpose = helpers.PurposeType[2]
	mpget = MPatchGet(purpose)
	mpjwt = MPatchVerifyJWTSignature(false, tErr)
	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{PrimaryEmailVerificationOTP: tErr})

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})
	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
	}

	mpjwt.Unpatch()
	mpjwt = MPatchVerifyJWTSignature(true, tErr)

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})
	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
		if res.Data["remarks"] != "OTP DID NOT MATCH" {
			t.Error("unexpected value of remarks -,", "expected- ", "OTP DID NOT MATCH", " received - ", res)
		}
	}

	mpdj.Unpatch()

	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{PrimaryEmailVerificationOTP: purpose})

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
		if res.Data["remarks"] != "OTP EXPIRED" {
			t.Error("unexpected value of remarks -,", "expected- ", "OTP EXPIRED", " received - ", res)
		}
	}

	mpdj.Unpatch()

	// here on, we are testing all the posible scenarios for userdata.Guardian field.

	mppub := MPatchPublish()
	mppubget := MPatchGetPubSub("", nil)

	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{PrimaryEmailOTPGenerateTimestamp: 2 * time.Now().Unix(), PrimaryEmailVerificationOTP: purpose, Guardians: []string{"", "", ""}, GuardianIdentifiers: []string{"", "", ""}})

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if !res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected true, received - ", res)
		}
	}

	mpdj.Unpatch()

	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{PrimaryEmailOTPGenerateTimestamp: 2 * time.Now().Unix(), PrimaryEmailVerificationOTP: purpose, Guardians: []string{"test", "test", "test"}, GuardianIdentifiers: []string{"", "", ""}})

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if !res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected true, received - ", res)
		}
	}

	// purpose 3

	mpdj.Unpatch()
	mpget.Unpatch()
	mpjwt.Unpatch()

	purpose = helpers.PurposeType[3]
	mpget = MPatchGet(purpose)
	mpjwt = MPatchVerifyJWTSignature(false, tErr)
	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{PrimaryEmailVerificationOTP: tErr})

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})
	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
	}

	mpjwt.Unpatch()
	mpjwt = MPatchVerifyJWTSignature(true, tErr)

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})
	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
		if res.Data["remarks"] != "OTP DID NOT MATCH" {
			t.Error("unexpected value of remarks -,", "expected- ", "OTP DID NOT MATCH", " received - ", res)
		}
	}

	mpdj.Unpatch()

	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{PrimaryEmailVerificationOTP: purpose})

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
		if res.Data["remarks"] != "OTP EXPIRED" {
			t.Error("unexpected value of remarks -,", "expected- ", "OTP EXPIRED", " received - ", res)
		}
	}

	mpdj.Unpatch()
	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{PrimaryEmailOTPGenerateTimestamp: 2 * time.Now().Unix(), PrimaryEmailVerificationOTP: purpose})

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if !res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected true, received - ", res)
		}
	}
	//  purpose 4

	mpdj.Unpatch()
	mpget.Unpatch()
	mpjwt.Unpatch()

	purpose = helpers.PurposeType[4]
	mpget = MPatchGet(purpose)
	mpjwt = MPatchVerifyJWTSignature(false, tErr)
	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{PrimaryEmailVerificationOTP: tErr})

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})
	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
	}

	mpjwt.Unpatch()
	mpjwt = MPatchVerifyJWTSignature(true, tErr)

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})
	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
		if res.Data["remarks"] != "OTP DID NOT MATCH" {
			t.Error("unexpected value of remarks -,", "expected- ", "OTP DID NOT MATCH", " received - ", res)
		}
	}

	mpdj.Unpatch()

	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{PrimaryEmailVerificationOTP: purpose})

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
		if res.Data["remarks"] != "OTP EXPIRED" {
			t.Error("unexpected value of remarks -,", "expected- ", "OTP EXPIRED", " received - ", res)
		}
	}

	mpdj.Unpatch()
	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{PrimaryEmailOTPGenerateTimestamp: 2 * time.Now().Unix(), PrimaryEmailVerificationOTP: purpose})

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if !res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected true, received - ", res)
		}
	}

	//  purpose 5

	mpdj.Unpatch()
	mpget.Unpatch()
	mpjwt.Unpatch()

	purpose = helpers.PurposeType[5]
	mpget = MPatchGet(purpose)
	mpjwt = MPatchVerifyJWTSignature(false, tErr)
	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{MobileVerificationOTP: tErr})

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})
	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
	}

	mpjwt.Unpatch()
	mpjwt = MPatchVerifyJWTSignature(true, tErr)

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})
	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
		if res.Data["remarks"] != "OTP DID NOT MATCH" {
			t.Error("unexpected value of remarks -,", "expected- ", "OTP DID NOT MATCH", " received - ", res)
		}
	}

	mpdj.Unpatch()

	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{MobileVerificationOTP: purpose})

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
		if res.Data["remarks"] != "OTP EXPIRED" {
			t.Error("unexpected value of remarks -,", "expected- ", "OTP EXPIRED", " received - ", res)
		}
	}

	mpdj.Unpatch()
	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{MobileOTPGenerateTimestamp: 2 * time.Now().Unix(), MobileVerificationOTP: purpose})

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if !res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected true, received - ", res)
		}
	}
	//  publish 6

	mpdj.Unpatch()
	mpget.Unpatch()
	mpjwt.Unpatch()

	purpose = helpers.PurposeType[6]
	mpget = MPatchGet(purpose)
	mpjwt = MPatchVerifyJWTSignature(false, tErr)
	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{MobileVerificationOTP: tErr})

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})
	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
	}

	mpjwt.Unpatch()
	mpjwt = MPatchVerifyJWTSignature(true, tErr)

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})
	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
		if res.Data["remarks"] != "OTP DID NOT MATCH" {
			t.Error("unexpected value of remarks -,", "expected- ", "OTP DID NOT MATCH", " received - ", res)
		}
	}

	mpdj.Unpatch()

	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{MobileVerificationOTP: purpose})

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected false, received - ", res)
		}
		if res.Data["remarks"] != "OTP EXPIRED" {
			t.Error("unexpected value of remarks -,", "expected- ", "OTP EXPIRED", " received - ", res)
		}
	}

	mpdj.Unpatch()
	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{MobileOTPGenerateTimestamp: 2 * time.Now().Unix(), MobileVerificationOTP: purpose, Guardians: []string{"", "", ""}, GuardianIdentifiers: []string{"", "", ""}})

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if !res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected true, received - ", res)
		}
	}
	mpdj.Unpatch()
	mpdj = MPatchDecodeJSONOverrideStruct(helpers.UserDetails{MobileOTPGenerateTimestamp: 2 * time.Now().Unix(), MobileVerificationOTP: purpose, Guardians: []string{"test", "test", "test"}, GuardianIdentifiers: []string{"", "", ""}})

	res, err = b.pathSubmitOTP(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error(" error wasn't expected, received - ", err)
	} else {
		if !res.Data["status"].(bool) {
			t.Error(" unexpected value of status,expected true, received - ", res)
		}
	}

	mppubget.Unpatch()
	mppub.Unpatch()
	mpjwt.Unpatch()
	mpAtoi.Unpatch()
	mpdj.Unpatch()
	mpget.Unpatch()
	mpnc.Unpatch()

}
