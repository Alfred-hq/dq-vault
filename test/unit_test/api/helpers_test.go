package tests

import (
	"context"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/golang/mock/gomock"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryadavDeqode/dq-vault/api/helpers"
	"github.com/ryadavDeqode/dq-vault/config"
	"github.com/ryadavDeqode/dq-vault/test/unit_test/mocks"
)

var mockPublicKeyPem = `-----BEGIN RSA PUBLIC KEY-----
MIIBigKCAYEAp6GwX4bYz2K1EnplU3M+wX1ureEwtiato0/VK+xW+dLY5Qjqw/cu
K3+3tEL+BTLSX0OB3Hyg5uQDbu/Gnmy5/JOUvlF77A/OHn9m4veFP8s5e/Fk7WMC
Wutl8MzlzVu9PYGOs7GWLw1WOXhjq4d4G2Rtq+iGNblFa8RVsVD6dVhVFGp3pBfv
NrJB8r0fjCjKwqgt0VyvAJfYxrDmxfP9taboYsfHCmb4HnjFWxk0cuebnocgqn/j
EzwY7OLqE6QePBEQWY0wCcMbh1BXTQ3YmaxMU5CYusOkLpVEaSXyvsFp4Kbu2E/q
4Z953sCqr06JM7FBnLdMnIzYdytMQ72/eog+Ylu1/8Eg+EbZUjFKGCbTsnpN6iCR
LqsmW8dVQHEfl4dwa1bWuBViiDnufAUmO/WHF5hE2ULpin89upJakgV1Dstkdcco
A3INdcwDs3Xwfl8gXnQtff4SeA7toSgXUqEIP+6yZpAfR1wcwLJBpzt2cnnKd2wM
CKup0+hQb/wPAgMBAAE=
-----END RSA PUBLIC KEY-----
`

var mockPublicKeyEncoded = `c3NoLXJzYSBBQUFBQjNOemFDMXljMkVBQUFBREFRQUJBQUFCZ1FDbm9iQmZodGpQWXJVU2VtVlRjejdCZlc2dDRUQzJKcTJqVDlVcjdGYjUwdGpsQ09yRDl5NHJmN2UwUXY0Rk10SmZRNEhjZktEbTVBTnU3OGFlYkxuOGs1UytVWHZzRDg0ZWYyYmk5NFUveXpsNzhXVHRZd0phNjJYd3pPWE5XNzA5Z1k2enNaWXZEVlk1ZUdPcmgzZ2JaRzJyNklZMXVVVnJ4Rld4VVBwMVdGVVVhbmVrRis4MnNrSHl2UitNS01yQ3FDM1JYSzhBbDlqR3NPYkY4LzIxcHVoaXg4Y0tadmdlZU1WYkdUUnk1NXVlaHlDcWYrTVRQQmpzNHVvVHBCNDhFUkJaalRBSnd4dUhVRmRORGRpWnJFeFRrSmk2dzZRdWxVUnBKZksrd1duZ3B1N1lUK3JobjNuZXdLcXZUb2t6c1VHY3QweWNqTmgzSzB4RHZiOTZpRDVpVzdYL3dTRDRSdGxTTVVvWUp0T3llazNxSUpFdXF5WmJ4MVZBY1IrWGgzQnJWdGE0RldLSU9lNThCU1k3OVljWG1FVFpRdW1LZnoyNmtscVNCWFVPeTJSMXh5Z0RjZzExekFPemRmQitYeUJlZEMxOS9oSjREdTJoS0JkU29RZy83ckpta0I5SFhCekFza0duTzNaeWVjcDNiQXdJcTZuVDZGQnYvQTg9IHRlc3Q=`

var mockPublicKeyPemEncode = `LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJpZ0tDQVlFQXA2R3dYNGJZejJLMUVucGxVM00rd1gxdXJlRXd0aWF0bzAvVksreFcrZExZNVFqcXcvY3UKSzMrM3RFTCtCVExTWDBPQjNIeWc1dVFEYnUvR25teTUvSk9VdmxGNzdBL09IbjltNHZlRlA4czVlL0ZrN1dNQwpXdXRsOE16bHpWdTlQWUdPczdHV0x3MVdPWGhqcTRkNEcyUnRxK2lHTmJsRmE4UlZzVkQ2ZFZoVkZHcDNwQmZ2Ck5ySkI4cjBmakNqS3dxZ3QwVnl2QUpmWXhyRG14ZlA5dGFib1lzZkhDbWI0SG5qRld4azBjdWVibm9jZ3FuL2oKRXp3WTdPTHFFNlFlUEJFUVdZMHdDY01iaDFCWFRRM1ltYXhNVTVDWXVzT2tMcFZFYVNYeXZzRnA0S2J1MkUvcQo0Wjk1M3NDcXIwNkpNN0ZCbkxkTW5JellkeXRNUTcyL2VvZytZbHUxLzhFZytFYlpVakZLR0NiVHNucE42aUNSCkxxc21XOGRWUUhFZmw0ZHdhMWJXdUJWaWlEbnVmQVVtTy9XSEY1aEUyVUxwaW44OXVwSmFrZ1YxRHN0a2RjY28KQTNJTmRjd0RzM1h3Zmw4Z1huUXRmZjRTZUE3dG9TZ1hVcUVJUCs2eVpwQWZSMXdjd0xKQnB6dDJjbm5LZDJ3TQpDS3VwMCtoUWIvd1BBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0t`

var mockPublicKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCnobBfhtjPYrUSemVTcz7BfW6t4TC2Jq2jT9Ur7Fb50tjlCOrD9y4rf7e0Qv4FMtJfQ4HcfKDm5ANu78aebLn8k5S+UXvsD84ef2bi94U/yzl78WTtYwJa62XwzOXNW709gY6zsZYvDVY5eGOrh3gbZG2r6IY1uUVrxFWxUPp1WFUUanekF+82skHyvR+MKMrCqC3RXK8Al9jGsObF8/21puhix8cKZvgeeMVbGTRy55uehyCqf+MTPBjs4uoTpB48ERBZjTAJwxuHUFdNDdiZrExTkJi6w6QulURpJfK+wWngpu7YT+rhn3newKqvTokzsUGct0ycjNh3K0xDvb96iD5iW7X/wSD4RtlSMUoYJtOyek3qIJEuqyZbx1VAcR+Xh3BrVta4FWKIOe58BSY79YcXmETZQumKfz26klqSBXUOy2R1xygDcg11zAOzdfB+XyBedC19/hJ4Du2hKBdSoQg/7rJmkB9HXBzAskGnO3Zyecp3bAwIq6nT6FBv/A8= test`

func TestNewUUID(t *testing.T) {
	uuid := helpers.NewUUID()
	len := len(uuid)
	if len == 0 {
		t.Error("uuid is of size 0")

	}
	if len != 20 {
		t.Error("uuid invalid!")
	}
}

func TestValidateFields(t *testing.T) {

	validateFields := helpers.ValidateFields(&logical.Request{}, &framework.FieldData{})

	if validateFields != nil {
		t.Error("expected nil!`")
	}
}

func TestStringInSlice(t *testing.T) {
	stringInSlc := helpers.StringInSlice("test", []string{"test"})

	if stringInSlc != true {
		t.Error("exptected true, returned false")
	}

	stringInSlc = helpers.StringInSlice("test", []string{""})

	if stringInSlc != false {
		t.Error("exptected false, returned true")
	}
}

func TestNew(t *testing.T) {
	new := helpers.New("test")

	if new == nil {
		t.Error("found nil, expected error.")
	}
}

func TestValidateData(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	m := mocks.NewMockStorage(ctrl)

	m.EXPECT().List(context.Background(), config.StorageBasePath).DoAndReturn(func(arg1 context.Context, arg2 string)([]string, error){
		return []string{}, nil
	}).Times(1)

	req := logical.Request{Storage: m}

	err := helpers.ValidateData(context.Background(), &req, "test_uuid", "/test/")

	if err == nil {
		t.Error("expected err. received - ", err)
	}

	m = mocks.NewMockStorage(ctrl)

	m.EXPECT().List(context.Background(), config.StorageBasePath).DoAndReturn(func(arg1 context.Context, arg2 string)([]string, error){
		return []string{"test_uuid"}, nil
	}).Times(1)

	req = logical.Request{Storage: m}

	err = helpers.ValidateData(context.Background(), &req, "test_uuid", "/test/")

	if err != nil {
		t.Error("expected nil. received - ", err)
	}

	err = helpers.ValidateData(context.Background(), &req, "test_uuid", "")

	if err == nil {
		t.Error("expected error, received - ", err.Error())
	}
}

func TestUUIDExists(t *testing.T){

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	m := mocks.NewMockStorage(ctrl)

	m.EXPECT().List(context.Background(), config.StorageBasePath).DoAndReturn(func(arg1 context.Context, arg2 string)([]string, error){
		return []string{}, nil
	}).Times(1)

	req := logical.Request{Storage: m}

	uuidExists := helpers.UUIDExists(context.Background(), &req, "test_uuid")

	if uuidExists{
		t.Error("expected false. received - ", uuidExists)
	}


	m = mocks.NewMockStorage(ctrl)

	m.EXPECT().List(context.Background(), config.StorageBasePath).DoAndReturn(func(arg1 context.Context, arg2 string)([]string, error){
		return []string{"test_uuid"}, nil
	}).Times(1)

	req = logical.Request{Storage: m}

	uuidExists = helpers.UUIDExists(context.Background(), &req, "test_uuid")

	if !uuidExists{
		t.Error("expected false. received - ", uuidExists)
	}

}

func TestGenerateOTP(t *testing.T) {
	otp, err := helpers.GenerateOTP(6)

	if err != nil {
		t.Error("received error", err)
	}

	if len(otp) != 6 {
		t.Error("invalid otp")
	}

	otp, err = helpers.GenerateOTP(0)

	if err != nil{
		t.Error(otp)
	}

}

func TestConvertPemToPublicKey(t *testing.T) {

	_, err := helpers.ConvertPemToPublicKey("test")

	if err == nil {
		t.Error("expected error!")
	}

	_, err = helpers.ConvertPemToPublicKey(mockPublicKeyPem)

	if err != nil {
		t.Error("expected valid public key, received error -> ", err)
	}
}

func TestVerifyRSASignedMessage(t *testing.T) {
	verifyRSA := helpers.VerifyRSASignedMessage("", "", "")

	if verifyRSA {
		t.Error("expected false")
	}

	verifyRSA = helpers.VerifyRSASignedMessage(mockPublicKeyEncoded, "test data", mockPublicKeyPemEncode)

	if verifyRSA{
		t.Error("expected false")
	}

	verifyRSA = helpers.VerifyRSASignedMessage(mockPublicKeyEncoded, "test data", mockPublicKeyPemEncode)

	if verifyRSA{
		t.Error("expected false")
	}
}

func TestVerifyECDSASignedMessage(t *testing.T) {
	verified := helpers.VerifyECDSASignedMessage("0x0135f8c1", "test_data", "test")

	if verified {
		t.Error("expected false")	
	}

	verified = helpers.VerifyECDSASignedMessage("0x0135f8c1", "test_data", "test")

	if verified {
		t.Error("expected false, ")	
	}

	verified = helpers.VerifyECDSASignedMessage("0x74657374", "test", "0x74657374")

	if verified{
		t.Error("expected false")	
	}

}

func TestVerifyTokenClaims(t *testing.T) {

	m := make(map[string]string)
	verified := helpers.VerifyTokenClaims(jwt.MapClaims{}, m)
	if !verified {
		t.Error("expected true, returned false")
	}
	m["test_k"] = "test_v"
	verified = helpers.VerifyTokenClaims(jwt.MapClaims{}, m)
	if verified {
		t.Error("expected false, returned true")
	}
}

func TestVerifyJWTSignature(t *testing.T){

	dataToValidate := make(map[string]string)
	
	_, errMsg := helpers.VerifyJWTSignature("", dataToValidate, "", "RS256")

	if errMsg != "token contains an invalid number of segments"{
		t.Error("errMsg was unexpected, received - ", errMsg)
	} 


	_, errMsg = helpers.VerifyJWTSignature("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", dataToValidate, "", "RS256")


	if errMsg != "RSA signature verification failed, token expired" {
		t.Error("errMsg was unexpected, received - ", errMsg)
	} 

	
}

