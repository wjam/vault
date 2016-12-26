package sshca

import (
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"strings"
	"sync"
)

func Factory(conf *logical.BackendConfig) (logical.Backend, error) {
	return Backend().Setup(conf)
}

func Backend() *backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),

		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"public_key",
				"crl",
			},
		},
		Paths: []*framework.Path{
			pathListRoles(&b),
			pathRoles(&b),
			pathConfigCA(&b),
			pathSign(&b),
			pathFetchCrl(&b),
			pathRevoke(&b),
			pathFetchPublicKey(&b),
			pathTidy(&b),
		},
		Secrets: []*framework.Secret{
			secretCerts(&b),
		},
	}

	return &b
}

type backend struct {
	*framework.Backend
	revokeStorageLock sync.RWMutex
}

const backendHelp = `
The SSH CA backend dynamically sign host and user certificates for use with SSH.

After mounting this backend, configure the CA using the "ca" endpoint within
the "config/" path.
`
