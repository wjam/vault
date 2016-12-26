package sshca

import (
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathRevoke(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: `revoke`,
		Fields: map[string]*framework.FieldSchema{
			"serial_number": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: ``,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathRevokeWrite,
		},

		HelpSynopsis:    `Revoke a certificate by serial number.`,
		HelpDescription: `This allows certificates to be revoked using its serial number.`,
	}
}

func (b *backend) pathRevokeWrite(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	serial := data.Get("serial_number").(string)
	if len(serial) == 0 {
		return logical.ErrorResponse("The serial number must be provided"), nil
	}

	b.revokeStorageLock.Lock()
	defer b.revokeStorageLock.Unlock()

	return revokeSSHCertificate(req, serial)
}
