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

func TestPathAddress(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := mocks.NewMockStorage(ctrl)
	b := backend{}
	req := logical.Request{}


	MPatchGet("test")
	MPatchDecodeJSON(nil)
	MPatchDerivePrivateKey("test", nil)
	MPatchDerivePublicKey("test", nil)

	s.EXPECT().Get(gomock.Any(), config.StorageBasePath+"test").Return(&logical.StorageEntry{}, nil)
	s.EXPECT().List(gomock.Any(), config.StorageBasePath).Return([]string{"test"}, nil)
	req.Storage = s

	res, err := b.pathAddress(context.Background(), &req, &framework.FieldData{})

	t.Error(res, err)

}