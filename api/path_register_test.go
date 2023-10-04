package api

import (
	"context"
	"errors"
	// "errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryadavDeqode/dq-vault/config"
	"github.com/ryadavDeqode/dq-vault/test/unit_test/mocks"
)

func TestPathRegister(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := mocks.NewMockStorage(ctrl)

	tErr := "test error"

	s.EXPECT().Put(context.Background(), gomock.Any()).Return(errors.New(tErr))
	s.EXPECT().List(context.Background(), config.StorageBasePath).Return([]string{"test"}, nil).AnyTimes()

	b := backend{}
	req := logical.Request{}

	req.Storage = s

	mpget := MPatchGet("")

	res, err := b.pathRegister(context.Background(), &req, &framework.FieldData{})

	if err == nil {
		t.Error("expected error, received", err, res)
	}

	s.EXPECT().Put(context.Background(), gomock.Any()).Return(nil).AnyTimes()
	res, err = b.pathRegister(context.Background(), &req, &framework.FieldData{})

	if err != nil {
		t.Error("expected no error, received", err, res)
	}



	mpStorageJson := MPatchEntryJSON(errors.New(tErr))

	res, err = b.pathRegister(context.Background(), &req, &framework.FieldData{})
	if err == nil {
		t.Error("expected error, received", err, res)
	}

	mpMnemonic := MPatchMnemonicFromEntropy(tErr, errors.New(tErr))
	res, err = b.pathRegister(context.Background(), &req, &framework.FieldData{})

	if err == nil {
		t.Error("expected error, received", err, res)
	} else if err.Error() != tErr {
		t.Error("unexpected error message", err, res)
	}

	mpValidateFields := MPatchValidateFields(errors.New(tErr))


	res, err = b.pathRegister(context.Background(), &req, &framework.FieldData{})

	if err == nil {
		t.Error("expected error, received", err, res)
	}

	mpValidateFields.Unpatch()
	mpStorageJson.Unpatch()
	mpget.Unpatch()
	mpMnemonic.Patch()

}
