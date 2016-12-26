package ssh

import (
	"github.com/go-errors/errors"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// SecretCertsType is the name used to identify this type
const SecretCertsType = "sshca"

func secretCerts(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: SecretCertsType,
		Fields: map[string]*framework.FieldSchema{
			"signed_key": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "The signd certificate.",
			},
			"serial_number": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `The serial number of the certificate, for handy
reference`,
			},
		},

		Revoke: b.secretCredsRevoke,
	}
}

func (b *backend) secretCredsRevoke(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if req.Secret == nil {
		return nil, errors.New("secret is nil in request")
	}

	serialNumber, ok := req.Secret.InternalData["serial_number"]
	if !ok {
		return nil, errors.New("could not find signed key in internal secret data")
	}

	b.revokeStorageLock.Lock()
	defer b.revokeStorageLock.Unlock()

	return revokeSSHCertificate(req, serialNumber.(string))
}
