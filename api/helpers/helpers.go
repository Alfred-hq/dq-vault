package helpers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/deqode/dq-vault/lib"
	"github.com/deqode/dq-vault/lib/bip44coins"
	"github.com/deqode/dq-vault/logger"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"net/http"
	"strconv"

	"github.com/deqode/dq-vault/config"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/rs/xid"

	log "github.com/sirupsen/logrus"
)

// User -- stores data related to user
type User struct {
	Username   string `json:"username"`
	UUID       string `json:"uuid"`
	Mnemonic   string `json:"mnemonic"`
	Passphrase string `json:"passphrase"`
}

type StarknetUser struct {
	UUID       string `json:"uuid"`
	Address    string `json:"address"`
	PrivateKey string `json:"privateKey"`
}

// NewUUID returns a globally unique random generated guid
func NewUUID() string {
	return xid.New().String()
}

// ErrMissingField returns a logical response error that prints a consistent
// error message for when a required field is missing.
func ErrMissingField(field string) *logical.Response {
	return logical.ErrorResponse(fmt.Sprintf("missing required field '%s'", field))
}

// ValidationErr returns an error that corresponds to a validation error.
func ValidationErr(msg string) error {
	return logical.CodedError(http.StatusUnprocessableEntity, msg)
}

// ValidateFields verifies that no bad arguments were given to the request.
func ValidateFields(req *logical.Request, data *framework.FieldData) error {
	var unknownFields []string
	for k := range req.Data {
		if _, ok := data.Schema[k]; !ok {
			unknownFields = append(unknownFields, k)
		}
	}

	return nil
}

// errorString is a trivial implementation of error.
type errorString struct {
	s string
}

func (e *errorString) Error() string {
	return e.s
}

// New returns an error that formats as the given text.
func New(text string) error {
	return &errorString{text}
}

// ValidateData - validates data provided provided to create signature
func ValidateData(ctx context.Context, req *logical.Request, uuid string, derivationPath string) error {
	// Check if user provided UUID or not
	if uuid == "" {
		return errors.New("Provide a valid UUID")
	}

	// base check: if derivation path is valid or not
	if derivationPath == "" {
		return errors.New("Provide a valid path")
	}

	if !UUIDExists(ctx, req, uuid) {
		return errors.New("UUID does not exists")
	}
	return nil
}

// UUIDExists checks if uuid exists or not
func UUIDExists(ctx context.Context, req *logical.Request, uuid string) bool {
	vals, err := req.Storage.List(ctx, config.StorageBasePath)
	if err != nil {
		return false
	}

	for _, val := range vals {
		if val == uuid {
			return true
		}
	}
	return false
}

// StarkUUIDExists checks if uuid exists for starknet user or not
func StarkUUIDExists(ctx context.Context, req *logical.Request, uuid string) bool {
	vals, err := req.Storage.List(ctx, config.StarkStorageBasePath)
	if err != nil {
		return false
	}

	for _, val := range vals {
		if val == uuid {
			return true
		}
	}
	return false
}

func ParseTypedDataRequest(ctx context.Context, req *logical.Request, d *framework.FieldData, backendLogger log.Logger) (int, []byte, string, apitypes.TypedData, string) {

	var message = d.Get("message").(map[string]interface{})
	var typedData = d.Get("typedData").(map[string]string)
	var domain = apitypes.TypedDataDomain{}
	var primaryType = d.Get("primaryType").(string)
	var types = d.Get("types").(string)

	for key, value := range typedData {
		if key == "name" {
			domain.Name = value
		} else if key == "version" {
			domain.Version = value
		} else if key == "chainId" {
			int_chain_id, err := strconv.Atoi(value)
			if err != nil {
				continue
			}
			domain.ChainId = math.NewHexOrDecimal256(int64(int_chain_id))
		} else {
			domain.VerifyingContract = value
		}
	}

	data := make(map[string][]apitypes.Type)

	err := json.Unmarshal([]byte(types), &data)

	if err != nil {
		fmt.Print(err)
	}

	var TypedData = apitypes.TypedData{
		PrimaryType: primaryType,
		Domain:      domain,
		Message:     message,
		Types:       data,
	}
	uuid := d.Get("uuid").(string)
	//
	//// derivation path
	derivationPath := d.Get("path").(string)
	//
	//// coin type of transaction
	//// see supported coinTypes lib/bipp44coins
	coinType := d.Get("coinType").(int)

	if uint16(coinType) == bip44coins.Bitshares {
		derivationPath = config.BitsharesDerivationPath
	}
	//////
	//logger.Log(backendLogger, config.Info, "signature:", fmt.Sprintf("request  path=[%v] cointype=%v payload=[%v]", derivationPath, coinType, payload))
	//////
	//////// validate data provided
	if err := ValidateData(ctx, req, uuid, derivationPath); err != nil {
		logger.Log(backendLogger, config.Error, "signature:", err.Error())
		return 0, nil, "", apitypes.TypedData{}, err.Error()
	}
	//////
	//////// path where user data is stored in vault
	path := config.StorageBasePath + uuid
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		logger.Log(backendLogger, config.Error, "signature:", err.Error())
		return 0, nil, "", apitypes.TypedData{}, err.Error()
	}
	//////
	//////// obtain mnemonic, passphrase of user
	var userInfo User
	err = entry.DecodeJSON(&userInfo)
	if err != nil {
		logger.Log(backendLogger, config.Error, "signature:", err.Error())
		return 0, nil, "", apitypes.TypedData{}, err.Error()
	}
	//////
	//////// obtain seed from mnemonic and passphrase
	seed, err := lib.SeedFromMnemonic(userInfo.Mnemonic, userInfo.Passphrase)

	return coinType, seed, derivationPath, TypedData, ""
}
