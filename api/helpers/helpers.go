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
	"github.com/dgrijalva/jwt-go"
	"github.com/ethereum/go-ethereum/common/hexutil"
	goCrypt "github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/rs/xid"
	"github.com/ryadavDeqode/dq-vault/config"
	"net/http"
	"strings"
	"time"
)

// User -- stores data related to user
type User struct {
	Username   string `json:"username"`
	UUID       string `json:"uuid"`
	Mnemonic   string `json:"mnemonic"`
	Passphrase string `json:"passphrase"`
}

var PurposeType = []string{
	"ADD_PRIMARY_EMAIL",
	"ADD_MOBILE_NUMBER",
	"VERIFY_EMAIL_FOR_WALLET_RESTORATION",
	"ADD_WALLET_THIRD_SHARD",
	"VERIFY_EMAIL_OTP",
	"VERIFY_MOBILE_OTP",
	"VERIFY_MOBILE_FOR_WALLET_RESTORATION",
}

type UserDetails struct {
	UserEmail                            string                   `json:"useremail"`
	UnverifiedUserEmail                  string                   `json:"tempuseremail"`
	Guardians                            []string                 `json:"guardians"`
	UnverifiedGuardians                  []string                 `json:"unverifiedGuardians"`
	GuardianEmailOTPGenerateTimestamp    []int64                  `json:"guardianEmailOTPGenerateTimestamp"`
	GuardiansAddLinkInitiation           []int64                  `json:"guardiansAddLinkInitiation"`
	GuardiansUpdateStatus                []bool                   `json:"guardiansUpdateStatus"`
	UserMobile                           string                   `json:"usermobile"`
	UnverifiedUserMobile                 string                   `json:"tempusermobile"`
	UserRSAPublicKey                     string                   `json:"userRSAPublicKey"`
	UserECDSAPublicKey                   string                   `json:"userECDSAPublicKey"`
	WalletThirdShard                     string                   `json:"secret"`
	LastRecoverySavedAt                  LastRecoverySaveLocation `json:"lastRecoverySavedAt"`
	UnverifiedWalletThirdShard           string                   `json:"unverifiedSecret"`
	Identifier                           string                   `json:"identifier"`
	IsRestoreInProgress                  bool                     `json:"isrestoreinprogress"`
	EmailVerificationState               bool                     `json:"emailverificationstate"`
	MobileVerificationState              bool                     `json:"mobileverificationstate"`
	PrimaryEmailVerificationOTP          string                   `json:"primaryEmailVerificationOTP"`
	GuardianIdentifiers                  []string                 `json:"guardianIdentifiers"`
	MobileVerificationOTP                string                   `json:"mobileverificationotp"`
	PrimaryEmailOTPGenerateTimestamp     int64                    `json:"primaryEmailOTPGenerateTimestamp"`
	MobileOTPGenerateTimestamp           int64                    `json:"mobileotpgeneratedtimestamp"`
	RestoreInitiationTimestamp           int64                    `json:"restoreinitiationtimestamp"`
	WalletIdentifierStoredAt             string                   `json:"walletIdentifierStoredAt"`
	SignedConsentForPrivateKey           string                   `json:"signedConsentForPrivateKey"`
	SignedConsentForMnemonics            string                   `json:"signedConsentForMnemonics"`
	LastVetoedBy                         string                   `json:"lastVetoedBy"`
	RsaEncryptedMnemonicEncryptionAESKey string                   `json:"rsaEncryptedMnemonicEncryptionAESKey"`
	UserWalletAddress                    string                   `json:"userWalletAddress"`
	LastVetoedAt                         int64                    `json:"lastVetoedAt"`
}

type LastRecoverySaveLocation struct {
	GoogleDriveFileId string `json:"googleDriveFileId"`
	IcloudFileId      string `json:"icloudFileId"`
	LocalFileId       string `json:"localFileId"`
}

type RestorationIdentifiers struct {
	UserRestorationIdentifier     string   `json:"userRestorationIdentifier"`
	GuardianRestorationIdentifier []string `json:"guardianRestorationIdentifier"`
}

type GuardianEmails struct {
	IsVerified bool   `json:"isVerified"`
	Value      string `json:"value"`
}

type VaultStatus struct {
	Identifier                 string                   `json:"identifier"`
	UserEmail                  string                   `json:"userEmail"`
	Guardians                  []GuardianEmails         `json:"guardians"`
	UserMobile                 string                   `json:"userMobile"`
	UserRSAPublicKey           bool                     `json:"userRSAPublicKey"`
	UserECDSAPublicKey         bool                     `json:"userECDSAPublicKey"`
	WalletThirdShard           bool                     `json:"secret"`
	LastRecoverySavedAt        LastRecoverySaveLocation `json:"lastRecoverySavedAt"`
	IsRestoreInProgress        bool                     `json:"isRestoreInProgress"`
	RestoreInitiationTimestamp int64                    `json:"restoreInitiationTimestamp"`
	RestoreCompletionTimestamp int64                    `json:"restoreCompletionTimestamp"`
	SignedConsentForPrivateKey bool                     `json:"signedConsentForPrivateKey"`
	SignedConsentForMnemonics  bool                     `json:"signedConsentForMnemonics"`
	LastVetoedBy               string                   `json:"lastVetoedBy"`
	LastVetoedAt               int64                    `json:"lastVetoedAt"`
}

type RecoveryDetails struct {
	ThirdShard                           string `json:"thirdShard"`
	RsaEncryptedMnemonicEncryptionAESKey string `json:"rsaEncryptedMnemonicEncryptionAESKey"`
}

type WalletIdentifierStorage struct {
	WalletIdentifier string `json:"walletIdentifier"`
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

func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
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
func VerifyRSASignedMessage(signatureEncoded string, data string, publicKeyEncoded string) bool {
	publicKeyPEM, err := base64.StdEncoding.DecodeString(publicKeyEncoded)
	if err != nil {
		fmt.Println("could not decode rsa key")
		return false
	}
	signature, err := base64.StdEncoding.DecodeString(signatureEncoded)
	if err != nil {
		fmt.Println("could not decode signature")
		return false
	}
	publicKey, err := ConvertPemToPublicKey(string(publicKeyPEM))
	if err != nil {
		fmt.Println("error with your key")
		return false
	}
	decodedSignature, _ := base64.StdEncoding.DecodeString(string(signature))
	messageBytes := []byte(data)
	messageDigest := sha256.Sum256(messageBytes)
	verifyErr := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, messageDigest[:], decodedSignature)
	if verifyErr != nil {
		return false
	}
	return true
}

func VerifyECDSASignedMessage(signature string, rawData string, publickKeyHash string) bool {
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

func VerifyTokenClaims(tokenClaims jwt.MapClaims, unsignedData map[string]string) bool {
	for k, v := range unsignedData {
		if tokenClaims[k] != v {
			return false
		}
	}
	return true
}

func VerifyJWTSignature(jwtToken string, dataToValidate map[string]string, publicKeyEncoded string, algorithm string) (bool, string) {
	jwtParsedToken, er := jwt.Parse(jwtToken, nil)
	if er.Error() == "token contains an invalid number of segments" {
		return false, er.Error()
	}
	parts := strings.Split(jwtToken, ".")
	jwtTokenClaims := jwtParsedToken.Claims.(jwt.MapClaims)
	isTokenExpired := !(jwtTokenClaims.VerifyExpiresAt(time.Now().Unix(), true))
	tokenClaimsVerification := VerifyTokenClaims(jwtTokenClaims, dataToValidate)
	if algorithm == "RS256" {
		if isTokenExpired == true {
			return false, "RSA signature verification failed, token expired"
		}
		if tokenClaimsVerification == false {
			return false, "rsa signature verification failed, payload mismatches with signed data"
		}
		publicKeyPEM, err := base64.StdEncoding.DecodeString(publicKeyEncoded)
		if err != nil {
			return false, "issue with Public RSA Key"
		}
		pubBlock, _ := pem.Decode(publicKeyPEM)
		pub, _ := x509.ParsePKCS1PublicKey(pubBlock.Bytes)
		err = jwt.SigningMethodRS256.Verify(strings.Join(parts[0:2], "."), parts[2], pub)
		if err != nil {
			return false, "RSA signature verification failed"
		}
		return true, "RSA Signature Verified"
	} else {
		if isTokenExpired == true {
			return false, "ECDSA signature verification failed, token expired"
		}
		if tokenClaimsVerification == false {
			return false, "ECDSA signature verification failed, payload mismatches with signed data"
		}

		signatureDecoded, _ := base64.StdEncoding.DecodeString(parts[2])
		ecdsaVerificationState := VerifyECDSASignedMessage(string(signatureDecoded), strings.Join(parts[0:2], "."), publicKeyEncoded)
		if ecdsaVerificationState == false {
			return false, "ECDSA signature verification failed"
		}
		return true, "ECDSA Signature Verified"
	}
}

type MailFormatVerification struct {
	To            string
	Otp           string
	Purpose       string
	MFASource     string // enum
	WalletAddress string
}

type MailFormatGuardianAdditionLink struct {
	To               string
	Purpose          string
	MFASource        string
	WalletIdentifier string
	Path             string
	UserEmail        string
	WalletAddress    string
}

type MailFormatGuardianVerified struct {
	To            string
	Purpose       string
	MFASource     string
	WalletAddress string
}

type MAILFormatUpdates struct {
	To                    string
	Purpose               string
	MFASource             string
	TimeOfInitiation      string
	WalletAddress         string
	RestorationIdentifier string
}

type MailFormatGuardian struct {
	To                    string
	Purpose               string
	WalletIdentifier      string
	GuardianIdentifier    string
	MFASource             string
	TimeOfInitiation      string
	TimeOfRestoration     string
	UserEmail             string
	WalletAddress         string
	RestorationIdentifier string
}

type MailFormatVetoed struct {
	To             string
	Purpose        string
	GuardianVetoed string
	MFASource      string
	VetoTime       string
	WalletAddress  string
}
