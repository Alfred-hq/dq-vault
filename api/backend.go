package api

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
)

// Factory creates a new usable instance of this secrets engine.
func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(c)
	if err := b.Setup(ctx, c); err != nil {
		return nil, errors.Wrap(err, "failed to create vault factory")
	}
	return b, nil
}

// backend is the actual backend.
type backend struct {
	*framework.Backend
	logger log.Logger
}

// Backend creates a new backend.
func Backend(c *logical.BackendConfig) *backend {
	var b backend

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        backendHelp,
		Paths: []*framework.Path{

			// api/register
			&framework.Path{
				Pattern:      "register",
				HelpSynopsis: "Registers a new user in vault",
				HelpDescription: `

Registers new user in vault using UUID. Generates mnemonics if not provided and store it in vault.
Returns randomly generated user UUID

`,
				Fields: map[string]*framework.FieldSchema{
					"username": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Username of new user (optional)",
						Default:     "",
					},
					"mnemonic": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Mnemonic of user (optional)",
						Default:     "",
					},
					"passphrase": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Passphrase of user (optional)",
						Default:     "",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathRegister,
				},
			},

			// api/signature
			&framework.Path{
				Pattern:         "signature",
				HelpSynopsis:    "Generate signature from raw transaction",
				HelpDescription: "Generates signature from stored mnemonic and passphrase using deviation path",
				Fields: map[string]*framework.FieldSchema{
					"uuid": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "UUID of user",
					},
					"path": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Deviation path to obtain keys",
						Default:     "",
					},
					"coinType": &framework.FieldSchema{
						Type:        framework.TypeInt,
						Description: "Cointype of transaction",
					},
					"payload": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Raw transaction payload",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathSignature,
				},
			},

			// api/sign
			&framework.Path{
				Pattern:         "sign",
				HelpSynopsis:    "Generate signature from raw transaction",
				HelpDescription: "Generates signature from stored mnemonic and passphrase using deviation path",
				Fields: map[string]*framework.FieldSchema{
					"uuid": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "UUID of user",
					},
					"path": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Deviation path to obtain keys",
						Default:     "",
					},
					"coinType": &framework.FieldSchema{
						Type:        framework.TypeInt,
						Description: "Cointype of transaction",
					},
					"payload": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Raw transaction payload",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathSign,
				},
			},

			// api/address
			&framework.Path{
				Pattern:         "address",
				HelpSynopsis:    "Generate address of user",
				HelpDescription: "Generates address from stored mnemonic and passphrase using deviation path",
				Fields: map[string]*framework.FieldSchema{
					"uuid": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "UUID of user",
					},
					"path": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Deviation path to address",
						Default:     "",
					},
					"coinType": &framework.FieldSchema{
						Type:        framework.TypeInt,
						Description: "Cointype of transaction",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathAddress,
				},
			},

			// api/info
			&framework.Path{
				Pattern:      "info",
				HelpSynopsis: "Display information about this plugin",
				HelpDescription: `

Displays information about the plugin, such as the plugin version and where to
get help.

`,
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ReadOperation: b.pathInfo,
				},
			},

			// api/addNewUser
			&framework.Path{
				Pattern:         "addNewUser",
				HelpSynopsis:    "addNewUser",
				HelpDescription: `Add new user details`,
				Fields: map[string]*framework.FieldSchema{
					"identifier": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "uuid identifier for path",
						Default:     "",
					},
					"signatureRSA": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "RSA signature",
						Default:     "",
					},
					"userRSAPublicKey": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "user RSA Public Key",
						Default:     "",
					},
					"signatureECDSA": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "ECDSA signature",
						Default:     "",
					},
					"userECDSAPublicKey": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "user ECDSA Public Key",
						Default:     "",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathNewUser,
				},
			},

			// api/addMFASource
			&framework.Path{
				Pattern:         "addMFASource",
				HelpSynopsis:    "addMFASource",
				HelpDescription: `Add new mfa source`,
				Fields: map[string]*framework.FieldSchema{
					"identifier": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "uuid identifier for path",
						Default:     "",
					},
					"signatureRSA": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "RSA signature",
						Default:     "",
					},
					"signatureECDSA": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "ECDSA signature",
						Default:     "",
					},
					"sourceType": &framework.FieldSchema{ // enum
						Type:        framework.TypeString,
						Description: "source type",
						Default:     "",
					},
					"sourceValue": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "source value",
						Default:     "",
					},
					"guardianIndex": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "guardian index",
						Default:     "",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathAddMFASource,
				},
			},

			// api/backupThirdShard
			&framework.Path{
				Pattern:         "backupThirdShard",
				HelpSynopsis:    "backupThirdShard",
				HelpDescription: `backup third shard`,
				Fields: map[string]*framework.FieldSchema{ // doubt
					"identifier": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "uuid identifier for path",
						Default:     "",
					},
					"signatureRSA": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "RSA signature",
						Default:     "",
					},
					"signatureECDSA": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "ECDSA signature",
						Default:     "",
					},
					"walletThirdShard": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "wallet third shard",
						Default:     "",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathBackupThirdShard,
				},
			},
			// api/submitOTP
			&framework.Path{
				Pattern:         "submitOTP",
				HelpSynopsis:    "submitOTP",
				HelpDescription: `submit otp`,
				Fields: map[string]*framework.FieldSchema{
					"identifier": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "uuid identifier for path",
						Default:     "",
					},
					"signatureRSA": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "RSA signature",
						Default:     "",
					},
					"signatureECDSA": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "ECDSA signature",
						Default:     "",
					},
					"purpose": &framework.FieldSchema{ // enum
						Type:        framework.TypeString,
						Description: "purpose of verification",
						Default:     "",
					},
					"otp": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "otp received on mail",
						Default:     "",
					},
					"guardianIndex": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "guardian index",
						Default:     "",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathSubmitOTP,
				},
			},

			// api/initiateWalletRestoration
			&framework.Path{
				Pattern:         "initiateWalletRestoration",
				HelpSynopsis:    "initiateWalletRestoration",
				HelpDescription: `initiate wallet restoration`,
				Fields: map[string]*framework.FieldSchema{
					"identifier": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "uuid identifier for path",
						Default:     "",
					},
					"signatureRSA": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "RSA signature",
						Default:     "",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathInitiateWalletRestoration,
				},
			},

			// api/cancelWalletRestoration
			&framework.Path{
				Pattern:         "cancelWalletRestoration",
				HelpSynopsis:    "cancelWalletRestoration",
				HelpDescription: `cancel wallet restoration`,
				Fields: map[string]*framework.FieldSchema{
					"identifier": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "uuid identifier for path",
						Default:     "",
					},
					"signatureRSA": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "RSA signature",
						Default:     "",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathCancelWalletRestoration,
				},
			},

			// api/getThirdShard
			&framework.Path{
				Pattern:         "getThirdShard",
				HelpSynopsis:    "getThirdShard",
				HelpDescription: `returns third wallet shard for restoration`,
				Fields: map[string]*framework.FieldSchema{
					"identifier": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "uuid identifier for path",
						Default:     "",
					},
					"signatureRSA": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "RSA signature",
						Default:     "",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathGetThirdShard,
				},
			},

			// api/veto
			&framework.Path{
				Pattern:         "veto",
				HelpSynopsis:    "veto",
				HelpDescription: `vetoes wallet restoration`,
				Fields: map[string]*framework.FieldSchema{
					"identifier": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "uuid identifier for path",
						Default:     "",
					},
					"guardianIdentifier": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "uuid identifier for guardian",
						Default:     "",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathVeto,
				},
			},

			&framework.Path{
				Pattern:         "guardians",
				HelpSynopsis:    "guardians",
				HelpDescription: `gets guardians`,
				Fields: map[string]*framework.FieldSchema{
					"identifier": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "uuid identifier for path",
						Default:     "",
					},
					"quest": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "uuid identifier for guardian",
						Default:     "",
					},
					"signatureRSA": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "RSA signature",
						Default:     "",
					},
					"signatureECDSA": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "ECDSA signature",
						Default:     "",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathGuardians,
				},
			},

			&framework.Path{
				Pattern:         "verifyGuardianForUpdate",
				HelpSynopsis:    "verify previous guardian for update!",
				HelpDescription: `verify previous guardian for update`,
				Fields: map[string]*framework.FieldSchema{
					"identifier": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "uuid identifier for path",
						Default:     "",
					},
					"guardianIndex": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "index of guardian to update",
						Default:     "",
					},
					"signatureRSA": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "RSA signature",
						Default:     "",
					},
					"signatureECDSA": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "ECDSA signature",
						Default:     "",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathUpdateGuardians,
				},
			},

			&framework.Path{
				Pattern:         "getIdentifier",
				HelpSynopsis:    "provides the identifier of wallet",
				HelpDescription: `provides the identifier of wallet`,
				Fields: map[string]*framework.FieldSchema{
					"userECDSAPublicKey": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "user ecdsa public key",
						Default:     "",
					},
					"signatureECDSA": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "ECDSA signature",
						Default:     "",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathGetIdentifier,
				},
			},

			&framework.Path{
				Pattern:         "updateRSAKeys",
				HelpSynopsis:    "updates user rsa key",
				HelpDescription: `updates user rsa key`,
				Fields: map[string]*framework.FieldSchema{
					"identifier": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "user identifier",
						Default:     "",
					},
					"userRSAPublicKey": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "user rsa public key",
						Default:     "",
					},
					"signatureECDSA": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "ECDSA signature",
						Default:     "",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathUpdateRSAKeys,
				},
			},
		},
	}
	return &b
}

const backendHelp = `
The API secrets engine serves as API for application server to store user information,
and optionally generate signed transaction from raw payload data.
`
