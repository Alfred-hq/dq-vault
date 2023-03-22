package api

import (
	"context"
	"fmt"
	reflect "reflect"

	"cloud.google.com/go/pubsub"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryadavDeqode/dq-vault/api/helpers"
	"github.com/undefinedlabs/go-mpatch"
	"google.golang.org/api/option"
)

//go:noinline
func MPatchDecodeJSON(rval error) (*mpatch.Patch, error) {
	var patch *mpatch.Patch
	var err error

	patch, err = mpatch.PatchInstanceMethodByName(reflect.TypeOf(&logical.StorageEntry{}), "DecodeJSON", func(arg1 *logical.StorageEntry, arg2 interface{}) error {
		patch.Unpatch()
		defer patch.Patch()
		return rval
	})

	if err != nil {
		fmt.Println("patching failed", err)
	}

	return patch, err
}

//go:noinline
func MPatchGet(rval string) (*mpatch.Patch, error) {

	var patch *mpatch.Patch
	var err error

	patch, err = mpatch.PatchInstanceMethodByName(reflect.TypeOf(&framework.FieldData{}), "Get", func(arg1 *framework.FieldData, arg2 string) interface{} {
		patch.Unpatch()
		defer patch.Patch()
		return rval
	})

	if err != nil {
		fmt.Println("patching failed", err)
	}

	return patch, err
}

//go:noinline
func MPatchVerifyJWTSignature(rval1 bool, rval2 string) (*mpatch.Patch, error) {

	var patch *mpatch.Patch
	var err error

	patch, err = mpatch.PatchMethod(helpers.VerifyJWTSignature, func(_ string, _ map[string]string, _ string, _ string) (arg1 bool, arg2 string) {
		patch.Unpatch()
		defer patch.Patch()
		return rval1, rval2
	})

	if err != nil {
		fmt.Println("patching failed", err)
	}

	return patch, err
}

//go:noinline
func MPatchNewClient() (*mpatch.Patch, error) {

	var patch *mpatch.Patch
	var err error

	patch, err = mpatch.PatchMethod(pubsub.NewClient, func(_ context.Context, _ string, opts ...option.ClientOption) (arg1 *pubsub.Client, arg2 error) {
		patch.Unpatch()
		defer patch.Patch()
		return &pubsub.Client{}, nil
	})

	if err != nil {
		fmt.Println("patching failed", err)
	}

	return patch, err
}


// func MPatchClientTopic(rval string) (*mpatch.Patch, error) {

// 	var patch *mpatch.Patch
// 	var err error

// 	patch, err = mpatch.PatchInstanceMethodByName(reflect.TypeOf(&framework.FieldData{}), "Get", func(arg1 *framework.FieldData, arg2 string) interface{} {
// 		patch.Unpatch()
// 		defer patch.Patch()
// 		return rval
// 	})

// 	if err != nil {
// 		fmt.Println("patching failed", err)
// 	}

// 	return patch, err
// }