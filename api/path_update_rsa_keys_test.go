package api

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryadavDeqode/dq-vault/config"
	"github.com/ryadavDeqode/dq-vault/test/unit_test/mocks"
	"github.com/sirupsen/logrus"
	"github.com/undefinedlabs/go-mpatch"
)


//go:noinline
func mPatchDecodeJSON(e logical.StorageEntry)(*mpatch.Patch, error){
	var patch *mpatch.Patch
	var err error

	 
	patch, err = mpatch.PatchInstanceMethodByName(reflect.TypeOf(&e), "DecodeJSON", func(arg1 *logical.StorageEntry, arg2 interface{}) error {
		patch.Unpatch()
		defer patch.Patch()
		return nil
	})
	
	if err != nil{
		fmt.Println("patching failed", err)
	}
	
	return patch, err
}
//go:noinline
func mPatchGet()(*mpatch.Patch, error, logical.StorageEntry){
	
	var patch *mpatch.Patch
	var err error

	patch, err = mpatch.PatchInstanceMethodByName(reflect.TypeOf(&framework.FieldData{}), "Get", func(arg1 *framework.FieldData, arg2 string) interface{} {
		patch.Unpatch()
		defer patch.Patch()
		return "test"
	})

	if err != nil{
		fmt.Println("patching failed", err)
	}

	return patch, err, e
}

//go:noinline
func TestPathUpdateRSAKeys(t *testing.T) {

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()


	mPatchGet()
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
	
	mPatchDecodeJSON()

	_, err = b.pathUpdateRSAKeys(context.Background(), &req, &d)

	if err != nil{
		t.Error(err)
	}
}

type MockFieldData struct {
	framework.FieldData
}

func (m *MockFieldData) GET(arg1 string) interface{} {
	return nil
}