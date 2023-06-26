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

			// api/signTypedv4
			&framework.Path{
				Pattern:         "signTypedv4",
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
					"message": &framework.FieldSchema{
						Type:        framework.TypeMap,
						Description: "Raw transaction payload",
					},
					"typedData": &framework.FieldSchema{
						Type:        framework.TypeKVPairs,
						Description: "Raw transaction payload",
					},
					"types": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Raw transaction payload",
					},
					"primaryType": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Raw transaction payload",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathSignTyped,
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

			//api/registerStarkUser
			&framework.Path{
				Pattern:         "registerStarkUser",
				HelpSynopsis:    "Generate address of user",
				HelpDescription: "Generates address from stored mnemonic and passphrase using deviation path",
				Fields: map[string]*framework.FieldSchema{
					"ethSignature": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "eth signature signed on the derivation message",
					},
					"address": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "payloadHash",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathRegisterStarknetUser,
				},
			},

			//api/starkSignature
			&framework.Path{
				Pattern:         "starkSignature",
				HelpSynopsis:    "Generate address of user",
				HelpDescription: "Generates address from stored mnemonic and passphrase using deviation path",
				Fields: map[string]*framework.FieldSchema{
					"payloadHash": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "payloadHash",
					},
					"starkUUID": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "stark UUID of user",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathStarkSignature,
				},
			},

			// api/starkPublicKeysTypedV4
			&framework.Path{
				Pattern:         "starkPublicKeysTypedV4",
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
					"message": &framework.FieldSchema{
						Type:        framework.TypeMap,
						Description: "Raw transaction payload",
					},
					"typedData": &framework.FieldSchema{
						Type:        framework.TypeKVPairs,
						Description: "Raw transaction payload",
					},
					"types": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Raw transaction payload",
					},
					"primaryType": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Raw transaction payload",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathStarkPublicKeysTyped,
				},
			},

			//api/starkSignatureTypedV4
			&framework.Path{
				Pattern:         "starkSignatureTypedV4",
				HelpSynopsis:    "Generate address of user",
				HelpDescription: "Generates address from stored mnemonic and passphrase using deviation path",
				Fields: map[string]*framework.FieldSchema{
					"payloadHash": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "payloadHash",
					},
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
					"message": &framework.FieldSchema{
						Type:        framework.TypeMap,
						Description: "Raw transaction payload",
					},
					"typedData": &framework.FieldSchema{
						Type:        framework.TypeKVPairs,
						Description: "Raw transaction payload",
					},
					"types": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Raw transaction payload",
					},
					"primaryType": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Raw transaction payload",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathStarkSignatureTyped,
				},
			},

			//api/starkPublicKeys
			&framework.Path{
				Pattern:         "starkPublicKeys",
				HelpSynopsis:    "Generate address of user",
				HelpDescription: "Generates address from stored mnemonic and passphrase using deviation path",
				Fields: map[string]*framework.FieldSchema{
					"starkUUID": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "stark UUID of user",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathStarkPublicKeys,
				},
			},

			&framework.Path{
				Pattern:      "healthCheck",
				HelpSynopsis: "checks if plugin is working correctly or not",
				HelpDescription: `

returns status of api plugin

`,
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ReadOperation: b.pathHealthCheck,
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
		},
	}
	return &b
}

const backendHelp = `
The API secrets engine serves as API for application server to store user information,
and optionally generate signed transaction from raw payload data.
`
