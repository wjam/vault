package sshca

import (
	"fmt"
	"time"

	"github.com/fatih/structs"
	"github.com/go-errors/errors"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathListRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRoleList,
		},

		HelpSynopsis:    `List the existing roles in this backend.`,
		HelpDescription: `Roles will be listed by the role name.`,
	}
}

func pathRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the role",
			},

			"ttl": &framework.FieldSchema{
				Type:    framework.TypeString,
				Default: "",
				Description: `The lease duration if no specific lease duration is
requested. The lease duration controls the expiration
of certificates issued by this backend. Defaults to
the value of max_ttl.`,
			},

			"max_ttl": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "",
				Description: "The maximum allowed lease duration",
			},

			"allowed_critical_options": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `A comma-separated list of critical options that certificates can have when signed.
 To allow any critical options, set this to an empty string.`,
			},

			"allowed_extensions": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `A comma-separated list of extensions that certificates can have when signed.
 To allow any critical options, set this to an empty string.`,
			},

			"default_critical_options": &framework.FieldSchema{
				Type:        framework.TypeMap,
				Description: `Critical options certificates should have if none are provided when signing.`,
			},

			"default_extensions": &framework.FieldSchema{
				Type:        framework.TypeMap,
				Description: `Extensions certificates should have if none are provided when signing.`,
			},

			"allow_user_certificates": &framework.FieldSchema{
				Type:        framework.TypeBool,
				Description: `If set, certificates are allowed to be signed for use as a 'user'.`,
				Default:     true,
			},

			"allow_host_certificates": &framework.FieldSchema{
				Type:        framework.TypeBool,
				Description: `If set, certificates are allowed to be signed for use as a 'host'.`,
				Default:     true,
			},

			"allowed_valid_principals": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `Comma separated list of valid principals that signing certificates can request a subset of
or an empty string if any, including none, are valid. Treated as a list of domains for 'host' certificate types`,
			},

			"allow_bare_domains": &framework.FieldSchema{
				Type: framework.TypeBool,
				Description: `If set, host certificates that are requested are allowed to use the base domains listed in
"allowed_valid_principals", e.g. "example.com".
This is a separate option as in some cases this can
be considered a security threat.`,
			},

			"allow_subdomains": &framework.FieldSchema{
				Type:        framework.TypeBool,
				Description: `If set, host certificates that are requested are allowed to use subdomains of those listed in "allowed_valid_principals".`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathRoleRead,
			logical.UpdateOperation: b.pathRoleCreate,
			logical.DeleteOperation: b.pathRoleDelete,
		},

		HelpSynopsis:    `Manage the roles that can be created with this backend.`,
		HelpDescription: `This path lets you manage the roles that can be created with this backend.`,
	}
}

func (b *backend) getRole(s logical.Storage, n string) (*roleEntry, error) {
	entry, err := s.Get("role/" + n)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result roleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) pathRoleDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete("role/" + data.Get("name").(string))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRoleRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role, err := b.getRole(req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	hasMax := true
	if len(role.MaxTTL) == 0 {
		role.MaxTTL = "(system default)"
		hasMax = false
	}
	if len(role.TTL) == 0 {
		if hasMax {
			role.TTL = "(system default, capped to role max)"
		} else {
			role.TTL = "(system default)"
		}
	}

	resp := &logical.Response{
		Data: structs.New(role).Map(),
	}

	if resp.Data == nil {
		return nil, errors.New("error converting role data to response")
	}

	return resp, nil
}

func (b *backend) pathRoleList(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List("role/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathRoleCreate(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error
	name := data.Get("name").(string)

	entry := &roleEntry{
		MaxTTL: data.Get("max_ttl").(string),
		TTL:    data.Get("ttl").(string),
		AllowedCriticalOptions: data.Get("allowed_critical_options").(string),
		AllowedExtensions:      data.Get("allowed_extensions").(string),
		AllowUserCertificates:  data.Get("allow_user_certificates").(bool),
		AllowHostCertificates:  data.Get("allow_host_certificates").(bool),
		AllowedValidPrincipals: data.Get("allowed_valid_principals").(string),
		AllowBareDomains:       data.Get("allow_bare_domains").(bool),
		AllowSubdomains:        data.Get("allow_subdomains").(bool),
	}

	defaultCriticalOptions := convertMapToStringValue(data.Get("default_critical_options").(map[string]interface{}))
	defaultExtensions := convertMapToStringValue(data.Get("default_extensions").(map[string]interface{}))

	var maxTTL time.Duration
	maxSystemTTL := b.System().MaxLeaseTTL()
	if len(entry.MaxTTL) == 0 {
		maxTTL = maxSystemTTL
	} else {
		maxTTL, err = time.ParseDuration(entry.MaxTTL)
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf(
				"Invalid ttl: %s", err)), nil
		}
	}
	if maxTTL > maxSystemTTL {
		return logical.ErrorResponse("Requested max TTL is higher than backend maximum"), nil
	}

	ttl := b.System().DefaultLeaseTTL()
	if len(entry.TTL) != 0 {
		ttl, err = time.ParseDuration(entry.TTL)
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf(
				"Invalid ttl: %s", err)), nil
		}
	}
	if ttl > maxTTL {
		// If they are using the system default, cap it to the role max;
		// if it was specified on the command line, make it an error
		if len(entry.TTL) == 0 {
			ttl = maxTTL
		} else {
			return logical.ErrorResponse(
				`"ttl" value must be less than "max_ttl" and/or backend default max lease TTL value`,
			), nil
		}
	}

	// Persist clamped TTLs
	entry.TTL = ttl.String()
	entry.MaxTTL = maxTTL.String()
	entry.DefaultCriticalOptions = defaultCriticalOptions
	entry.DefaultExtensions = defaultExtensions

	// Store it
	jsonEntry, err := logical.StorageEntryJSON("role/"+name, entry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(jsonEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

type roleEntry struct {
	MaxTTL                 string            `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`
	TTL                    string            `json:"ttl" structs:"ttl" mapstructure:"ttl"`
	DefaultCriticalOptions map[string]string `json:"default_critical_options" structs:"default_critical_options" mapstructure:"default_critical_options"`
	DefaultExtensions      map[string]string `json:"default_extensions" structs:"default_extensions" mapstructure:"default_extensions"`
	AllowedCriticalOptions string            `json:"allowed_critical_options" structs:"allowed_critical_options" mapstructure:"allowed_critical_options"`
	AllowedExtensions      string            `json:"allowed_extensions" structs:"allowed_extensions" mapstructure:"allowed_extensions"`
	AllowUserCertificates  bool              `json:"allow_user_certificates" structs:"allow_user_certificates" mapstructure:"allow_user_certificates"`
	AllowHostCertificates  bool              `json:"allow_host_certificates" structs:"allow_host_certificates" mapstructure:"allow_host_certificates"`
	AllowedValidPrincipals string            `json:"allowed_valid_principals" structs:"allowed_valid_principals" mapstructure:"allowed_valid_principals"`
	AllowBareDomains       bool              `json:"allow_bare_domains" structs:"allow_bare_domains" mapstructure:"allow_bare_domains"`
	AllowSubdomains        bool              `json:"allow_subdomains" structs:"allow_subdomains" mapstructure:"allow_subdomains"`
}
