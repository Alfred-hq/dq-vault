package helpers

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	goCrypt "github.com/ethereum/go-ethereum/crypto"
	"net/http"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/rs/xid"
	"github.com/ryadavDeqode/dq-vault/config"
)

// User -- stores data related to user
type User struct {
	Username   string `json:"username"`
	UUID       string `json:"uuid"`
	Mnemonic   string `json:"mnemonic"`
	Passphrase string `json:"passphrase"`
}

type UserDetails struct {
	UserEmail                  string `json:"useremail"`
	TempUserEmail              string `json:"tempuseremail"`
	GuardianEmail1             string `json:"guardianemail1"`
	TempGuardianEmail1         string `json:"tempguardianemail1"`
	GuardianEmail2             string `json:"guardianemail2"`
	TempGuardianEmail2         string `json:"tempguardianemail2"`
	GuardianEmail3             string `json:"guardianemail3"`
	TempGuardianEmail3         string `json:"tempguardianemail3"`
	UserMobile                 string `json:"usermobile"`
	TempUserMobile             string `json:"tempusermobile"`
	UserRSAPublicKey           string `json:"userRSAPublicKey"`
	UserECDSAPublicKey         string `json:"userECDSAPublicKey"`
	Secret                     string `json:"secret"`
	Identifier                 string `json:"identifier"`
	IsRestoreInProgress        bool   `json:"isrestoreinprogress"`
	EmailVerificationState     bool   `json:"emailverificationstate"`
	MobileVerificationState    bool   `json:"mobileverificationstate"`
	EmailVerificationOTP       string `json:"emailverificationotp"`
	MobileVerificationOTP      string `json:"mobileverificationotp"`
	EmailOTPGenerateTimestamp  int64  `json:"emailverificationtimestamp"`
	MobileOTPGenerateTimestamp int64  `json:"mobileotpgeneratedtimestamp"`
	RestoreInitiationTimestamp int64  `json:"restoreinitiationtimestamp"`
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

const otpChars = "1234567890"

// GenerateOTP - generate random number of length passed
func GenerateOTP(length int) (string, error) {
	buffer := make([]byte, length)
	_, err := rand.Read(buffer)
	if err != nil {
		return "", err
	}

	otpCharsLength := len(otpChars)
	for i := 0; i < length; i++ {
		buffer[i] = otpChars[int(buffer[i])%otpCharsLength]
	}

	return string(buffer), nil
}

// converts pem format to rsa public key
func ConvertPemToPublicKey(publicKeyPem string) (*rsa.PublicKey, error) {
	pubBlock, _ := pem.Decode([]byte(publicKeyPem))
	if pubBlock == nil {
		return nil, errors.New("problem with rsa key passed")
	}
	pub, _ := x509.ParsePKCS1PublicKey(pubBlock.Bytes)
	return pub, nil
}

// verifies if data is signed using passed public key
func VerifySignedData(signature string, data string, publicKeyPEM string) bool {
	publicKey, err := ConvertPemToPublicKey(publicKeyPEM)
	if err != nil {
		fmt.Println("error with your key")
		return false
	}
	decodedSignature, _ := base64.StdEncoding.DecodeString(signature)
	messageBytes := []byte(data)
	messageDigest := sha256.Sum256(messageBytes)
	verifyErr := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, messageDigest[:], decodedSignature)
	if verifyErr != nil {
		return false
	}
	return true
}

func verifyECDSASignedMessage(signature string, publickKeyHash string, rawData string) bool {
	rawDataBytes := []byte(rawData)
	messageHash := goCrypt.Keccak256Hash(rawDataBytes)
	decodedSignatureBytesFromHash, err := hexutil.Decode(signature)
	if err != nil {
		return false
	}
	signatureBytesWithNoRecoverID := decodedSignatureBytesFromHash[:len(decodedSignatureBytesFromHash)-1]
	pubKeyBytes, err := hex.DecodeString(publickKeyHash[2:])
	if err != nil {
		return false
	}
	verified := goCrypt.VerifySignature(pubKeyBytes, messageHash.Bytes(), signatureBytesWithNoRecoverID)
	return verified
}

// GenerateKeys - generates rsa public and private keys of passed size
func GenerateKeys(size int) (*rsa.PrivateKey, rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		fmt.Println("error occurred", err)
	}
	publicKey := privateKey.PublicKey
	return privateKey, publicKey
}
