package api

import (
	"context"
	"fmt"
	reflect "reflect"
	"strconv"
	"strings"

	"cloud.google.com/go/pubsub"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ryadavDeqode/dq-vault/api/helpers"
	"github.com/ryadavDeqode/dq-vault/lib"
	"github.com/ryadavDeqode/dq-vault/lib/adapter"
	"github.com/sirupsen/logrus"
	"github.com/undefinedlabs/go-mpatch"
	"google.golang.org/api/option"
)

//go:noinline
func MPatchDecodeJSON(rval error) *mpatch.Patch {
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

	return patch
}

//go:noinline
func MPatchDecodeJSONOverrideStruct(userData helpers.UserDetails) *mpatch.Patch {
	var patch *mpatch.Patch
	var err error

	patch, err = mpatch.PatchInstanceMethodByName(reflect.TypeOf(&logical.StorageEntry{}), "DecodeJSON", func(arg1 *logical.StorageEntry, arg2 interface{}) error {
		patch.Unpatch()
		defer patch.Patch()

		if val, ok := arg2.(*helpers.UserDetails); ok {
			val.Guardians = userData.Guardians
			val.UnverifiedGuardians = userData.UnverifiedGuardians
			val.GuardiansAddLinkInitiation = userData.GuardiansAddLinkInitiation
			val.GuardianIdentifiers = userData.GuardianIdentifiers
			val.IsRestoreInProgress = userData.IsRestoreInProgress
			val.RestoreInitiationTimestamp = userData.RestoreInitiationTimestamp
			val.PrimaryEmailVerificationOTP = userData.PrimaryEmailVerificationOTP
			val.PrimaryEmailOTPGenerateTimestamp = userData.PrimaryEmailOTPGenerateTimestamp
			val.MobileVerificationOTP = userData.MobileVerificationOTP
			val.MobileOTPGenerateTimestamp = userData.MobileOTPGenerateTimestamp
			val.UserEmail = userData.UserEmail

		} else {
			fmt.Print(val, ok)
		}

		return nil
	})

	if err != nil {
		fmt.Println("patching failed", err)
	}

	return patch
}

//go:noinline
func MPatchGet(rval interface{}) *mpatch.Patch {

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

	return patch
}

//go:noinline
func MPatchVerifyJWTSignature(rval1 bool, rval2 string) *mpatch.Patch {

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

	return patch
}

//go:noinline
func MPatchNewClient(rErr error) *mpatch.Patch {

	var patch *mpatch.Patch
	var err error

	patch, err = mpatch.PatchMethod(pubsub.NewClient, func(_ context.Context, _ string, opts ...option.ClientOption) (arg1 *pubsub.Client, arg2 error) {
		patch.Unpatch()
		defer patch.Patch()
		if rErr != nil {
			return nil, rErr
		}
		return &pubsub.Client{}, nil
	})

	if err != nil {
		fmt.Println("patching failed", err)
	}

	return patch
}

func MPatchAtoi(rErr error) *mpatch.Patch {

	var patch *mpatch.Patch
	var err error

	patch, err = mpatch.PatchMethod(strconv.Atoi, func(_ string) (arg1 int, arg2 error) {
		patch.Unpatch()
		defer patch.Patch()
		if rErr != nil {
			return 0, rErr
		}
		fmt.Print(rErr)
		return 0, nil
	})

	if err != nil {
		fmt.Println("patching failed", err)
	}

	return patch
}

// func MPatchDerivePrivateKey(rVal string, rErr error) *mpatch.Patch {

// 	var patch *mpatch.Patch
// 	var err error

// 	a := new(adapter.BitcoinAdapter)

// 	patch, err = mpatch.PatchInstanceMethodByName(reflect.TypeOf(&a), "DerivePrivateKey", func(_ *baseadapter.IBlockchainAdapter, _ logrus.Logger) (string, error) {
// 		patch.Unpatch()
// 		defer patch.Patch()
// 		return rVal, rErr
// 	})

// 	if err != nil {
// 		fmt.Println("patching failed", err)
// 	}

// 	return patch

// }

func MPatchMnemonicFromEntropy(rVal string, rErr error) *mpatch.Patch {

	var patch *mpatch.Patch
	var err error

	patch, err = mpatch.PatchMethod(lib.MnemonicFromEntropy, func(arg1 int) (string, error) {
		patch.Unpatch()
		defer patch.Patch()
		return rVal, rErr
	})

	if err != nil {
		fmt.Println("patching failed", err)
	}

	return patch
}

func MPatchStringInSlice(rVal bool) *mpatch.Patch {

	var patch *mpatch.Patch
	var err error

	patch, err = mpatch.PatchMethod(helpers.StringInSlice, func(_ string, list []string) bool {
		patch.Unpatch()
		defer patch.Patch()
		return rVal
	})

	if err != nil {
		fmt.Println("patching failed", err)
	}

	return patch
}

func MPatchGetPubSub(serverID string, e error) *mpatch.Patch {

	var patch *mpatch.Patch
	var err error

	a := pubsub.PublishResult{}

	patch, err = mpatch.PatchInstanceMethodByName(reflect.TypeOf(&a), "Get", func(_ *pubsub.PublishResult, _ context.Context) (string, error) {
		patch.Unpatch()
		defer patch.Patch()
		return serverID, e
	})

	if err != nil {
		fmt.Println("patching failed", err)
	}

	return patch
}

func MPatchSplitString(rVal []string) *mpatch.Patch {
	var patch *mpatch.Patch
	var err error

	patch, err = mpatch.PatchMethod(strings.Split, func(_ string, _ string) (list []string) {
		patch.Unpatch()
		defer patch.Patch()
		return rVal
	})

	if err != nil {
		fmt.Println("patching failed", err)
	}

	return patch
}

func MPatchDerivePrivateKey(rVal string, errVal error) *mpatch.Patch {

	var patch *mpatch.Patch
	var err error

	a, err := adapter.GetAdapter(0, []byte{}, "")
	// a := adapter.BitcoinAdapter{}

	fmt.Print(err)

	patch, err = mpatch.PatchInstanceMethodByName(reflect.TypeOf(a), "DerivePrivateKey", func(_ *adapter.BitcoinAdapter, _ logrus.Logger) (string, error) {
		patch.Unpatch()
		defer patch.Patch()
		return rVal, errVal
	})

	if err != nil {
		fmt.Println("patching failed", err)
	}

	return patch
}

func MPatchDerivePublicKey(rVal string, errVal error) *mpatch.Patch {

	var patch *mpatch.Patch
	var err error

	a, err := adapter.GetAdapter(0, []byte{}, "")
	// a := adapter.BitcoinAdapter{}

	patch, err = mpatch.PatchInstanceMethodByName(reflect.TypeOf(a), "DerivePublicKey", func(_ *adapter.BitcoinAdapter, _ logrus.Logger) (string, error) {
		patch.Unpatch()
		defer patch.Patch()
		return rVal, errVal
	})

	if err != nil {
		fmt.Println("patching failed", err)
	}

	return patch
}

func MPatchDeriveAddress(rVal string, errVal error) *mpatch.Patch {

	var patch *mpatch.Patch
	var err error

	a, _ := adapter.GetAdapter(0, []byte{}, "")
	// a := adapter.BitcoinAdapter{}

	patch, err = mpatch.PatchInstanceMethodByName(reflect.TypeOf(a), "DeriveAddress", func(_ *adapter.BitcoinAdapter, _ logrus.Logger) (string, error) {
		patch.Unpatch()
		defer patch.Patch()
		return rVal, errVal
	})

	if err != nil {
		fmt.Println("patching failed", err)
	}

	return patch
}

func MPatchCreateSignature(rVal string, errVal error) *mpatch.Patch {

	var patch *mpatch.Patch
	var err error

	a, err := adapter.GetAdapter(0, []byte{}, "")
	// a := adapter.BitcoinAdapter{}

	fmt.Print(err)

	patch, err = mpatch.PatchInstanceMethodByName(reflect.TypeOf(a), "CreateSignature", func(_ *adapter.BitcoinAdapter, _ string, _ logrus.Logger) (string, error) {
		patch.Unpatch()
		defer patch.Patch()
		return rVal, errVal
	})

	if err != nil {
		fmt.Println("patching failed", err)
	}

	return patch
}

func MPatchCreateSignedTransaction(rVal string, errVal error) *mpatch.Patch {

	var patch *mpatch.Patch
	var err error

	a, _ := adapter.GetAdapter(0, []byte{}, "")

	patch, err = mpatch.PatchInstanceMethodByName(reflect.TypeOf(a), "CreateSignedTransaction", func(_ *adapter.BitcoinAdapter, _ string, _ logrus.Logger) (string, error) {
		patch.Unpatch()
		defer patch.Patch()
		return rVal, errVal
	})

	if err != nil {
		fmt.Println("patching failed", err)
	}

	return patch
}

func MPatchPublish() *mpatch.Patch {

	var patch *mpatch.Patch
	var err error

	a := pubsub.Topic{}

	patch, err = mpatch.PatchInstanceMethodByName(reflect.TypeOf(&a), "Publish", func(_ *pubsub.Topic, _ context.Context, _ *pubsub.Message) *pubsub.PublishResult {
		patch.Unpatch()
		defer patch.Patch()
		return &pubsub.PublishResult{}
	})

	if err != nil {
		fmt.Println("patching failed", err)
	}

	return patch

}

// func MPatchSeedFromMnemonic(rVal)

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
