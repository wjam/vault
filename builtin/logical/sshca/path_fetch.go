package sshca

import (
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathFetchCrl(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: `crl`,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathFetchCrl,
		},

		HelpSynopsis:    `Retrieve the CRL.`,
		HelpDescription: `Fetch the current list of revoked certificates.`,
	}
}

func pathFetchPublicKey(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: `public_key`,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathFetchPublicKey,
		},

		HelpSynopsis:    `Retrieve the public key.`,
		HelpDescription: `This allows the public key, that this backend has been configured with, to be fetched.`,
	}
}

func (b *backend) pathFetchCrl(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	entry, err := req.Storage.Get("crl")
	if err != nil {
		return nil, err
	}

	response := &logical.Response{
		Data: map[string]interface{}{
			logical.HTTPContentType: "text/plain",
			logical.HTTPRawBody:     entry.Value,
			logical.HTTPStatusCode:  200,
		}}

	return response, nil

}

func (b *backend) pathFetchPublicKey(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	entry, err := req.Storage.Get("public_key")
	if err != nil {
		return nil, err
	}

	response := &logical.Response{
		Data: map[string]interface{}{
			logical.HTTPContentType: "text/plain",
			logical.HTTPRawBody:     entry.Value,
			logical.HTTPStatusCode:  200,
		}}

	return response, nil

}
