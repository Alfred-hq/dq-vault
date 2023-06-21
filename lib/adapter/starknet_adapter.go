package adapter

import (
	"encoding/hex"
	"fmt"
	"github.com/deqode/dq-vault/config"
	"github.com/deqode/dq-vault/lib/adapter/baseadapter"
	"github.com/deqode/dq-vault/lib/starkex"
	"github.com/deqode/dq-vault/logger"
	"golang.org/x/crypto/sha3"
	"math/big"

	log "github.com/sirupsen/logrus"
)

// StarknetAdapter - Ethereum blockchain transaction adapter
type StarknetAdapter struct {
	baseadapter.BlockchainAdapter
	zeroAddress string
}

// NewStarknetAdapter constructor function for StarknetAdapter
// sets seed, derivation path as internal data
func NewStarknetAdapter() *StarknetAdapter {
	adapter := new(StarknetAdapter)
	return adapter
}

func (e *StarknetAdapter) DeriveStarkPrivateKey(signature string, backendLogger log.Logger) (string, error) {

	// Fix raw signature
	typedSignature := signature + "00"

	hash := sha3.NewLegacyKeccak256()
	var buf []byte
	b, err := hex.DecodeString(typedSignature)

	if err != nil {
		logger.Log(backendLogger, config.Error, "signature:", err.Error())
		return "", err
	}

	hash.Write(b)
	buf = hash.Sum(nil)
	p := hex.EncodeToString(buf)
	n := new(big.Int)
	n.SetString(p, 16)

	privateKeyHex := fmt.Sprintf("%x", n.Rsh(n, 5))
	e.PrivateKey = privateKeyHex

	return privateKeyHex, nil
}

func (e *StarknetAdapter) DeriveStarkPublicKeyPair(backendLogger log.Logger) (string, string, error) {
	privateKey := e.PrivateKey
	publicKeyCoordinates, err := starkex.PrivateToPublicKeyPair(privateKey)

	if err != nil {
		logger.Log(backendLogger, config.Error, "signature:", err.Error())
		return "", "", err
	}

	return publicKeyCoordinates.X, publicKeyCoordinates.Y, nil
}

func (e *StarknetAdapter) CreateSignature(payload string, backendLogger log.Logger) (string, error) {
	signature := starkex.Sign(e.PrivateKey, payload)
	return signature, nil
}
