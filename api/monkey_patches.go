package api

import (
	"fmt"
	reflect "reflect"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/undefinedlabs/go-mpatch"
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