package api

import (
	"context"
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

	MPatchGet("test")
	var err error

	s := mocks.NewMockStorage(ctrl)

	s.EXPECT().Get(context.Background(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, nil).MinTimes(0)

	b := backend{&framework.Backend{}, logrus.Logger{}}

	req := logical.Request{Storage: s}

	d := framework.FieldData{}

	_, err = b.pathUpdateRSAKeys(context.Background(), &req, &d)

	if err == nil {
		t.Error("expected error!")
	}

	MPatchDecodeJSON(nil)

	_, err = b.pathUpdateRSAKeys(context.Background(), &req, &d)

	if err != nil {
		t.Error(err)
	}
}

type MockFieldData struct {
	framework.FieldData
}

func (m *MockFieldData) GET(arg1 string) interface{} {
	return nil
}