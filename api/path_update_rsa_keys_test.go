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
	"github.com/sirupsen/logrus"
)

func TestPathUpdateRSAKeys(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mpget := MPatchGet("test")

	tErr := "test error"

	s := mocks.NewMockStorage(ctrl)

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, errors.New(tErr))

	b := backend{&framework.Backend{}, logrus.Logger{}}

	req := logical.Request{Storage: s}

	d := framework.FieldData{}

	res, err := b.pathUpdateRSAKeys(context.Background(), &req, &d)

	if err == nil {
		t.Error("expected error!")
	}

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, nil).AnyTimes()

	_, err = b.pathUpdateRSAKeys(context.Background(), &req, &d)

	if err == nil {
		t.Error("expected error!")
	}

	mpdj := MPatchDecodeJSON(nil)

	_, err = b.pathUpdateRSAKeys(context.Background(), &req, &d)

	if err != nil {
		t.Error(err)
	}

	mpjwt := MPatchVerifyJWTSignature(true, tErr)

	mpEntryJson := MPatchEntryJSON(errors.New(tErr))

	res, err = b.pathUpdateRSAKeys(context.Background(), &req, &d)

	if err == nil {
		t.Error("expected error!")
	}

	mpEntryJson.Unpatch()
	mpEntryJson = MPatchEntryJSON(nil)

	s.EXPECT().Put(context.Background(), gomock.Any()).Return(errors.New(tErr))

	res, err = b.pathUpdateRSAKeys(context.Background(), &req, &d)

	if err == nil {
		t.Error("expected error!", "received", res)
	}

	s.EXPECT().Put(context.Background(), gomock.Any()).Return(nil).AnyTimes()

	res, err = b.pathUpdateRSAKeys(context.Background(), &req, &d)

	if !res.Data["status"].(bool) {

		t.Error("unpected data, expected status true, received, ", res)
	}

	mpEntryJson.Unpatch()
	mpjwt.Unpatch()
	mpdj.Unpatch()
	mpget.Unpatch()
}

// type MockFieldData struct {
// 	framework.FieldData
// }

// func (m *MockFieldData) GET(arg1 string) interface{} {
// 	return nil
// }
