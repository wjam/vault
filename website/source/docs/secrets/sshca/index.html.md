---
layout: "docs"
page_title: "Secret Backend: SSH CA"
sidebar_current: "docs-secrets-sshca"
description: |-
  The SSH CA secret backend for Vault managing the signing of SSH keys.
---

# SSH CA Secret Backend

Name: `sshca`

The Vault SSH CA backend generates SSH certificates for either authenticating a
users key against a remote host without sharing the public key beforehand or
allowing users to authenticate the remote hosts they are connecting to. This
allows giving users access to numerous remote hosts without having to manage the
correct handling of the individual SSH keys, such as revocation.

This page will show a quick start for this backend. For detailed documentation
on every path, use `vault path-help` after mounting the backend.

## Considerations

To successfully deploy this backend, there are a number of important
considerations to be aware of, as well as some preparatory steps that should be
undertaken. You should read all of these *before* using this backend or
generating the CA to use with this backend.

### One SSH CA Key, One Backend

To simplify both the configuration and the implementation of the SSH CA backend,
only one SSH CA key is allowed per-backend. 

If multiple CA keys are required, multiple backends can be used.

### Keep certificate lifetimes short, for CRL's sake

This backend aligns with Vault's philosophy of short-lived secrets. As such it
is not expected that CRLs will grow large; the only place a private key is ever
returned is to the requesting client (this backend does *not* store generated
private keys, except for CA certificates). In most cases, if the key is lost,
the certificate can simply be ignored, as it will expire shortly.

If a certificate must truly be revoked, the normal Vault revocation function
can be used; alternately a root token can be used to revoke the certificate
using the certificate's serial number. Any revocation action will cause the CRL
to be regenerated. When the CRL is regenerated, any expired certificates are
removed from the CRL (and any revoked, expired certificate are removed from
backend storage).

This backend does not support multiple CRL endpoints with sliding date windows;
often such mechanisms will have the transition point a few days apart, but this
gets into the expected realm of the actual certificate validity periods issued
from this backend. A good rule of thumb for this backend would be to simply not
issue certificates with a validity period greater than your maximum comfortable
CRL lifetime. Alternately, you can control CRL caching behavior on the client
to ensure that checks happen more often.

Often multiple endpoints are used in case a single CRL endpoint is down so that
clients don't have to figure out what to do with a lack of response. Run Vault
in HA mode, and the CRL endpoint should be available even if a particular node
is down.

### Token Lifetimes and Revocation

When a token expires, it revokes all leases associated with it. This means that
long-lived CA certs need correspondingly long-lived tokens, something that is
easy to forget. Starting with 0.6, root and intermediate CA certs no longer
have associated leases, to prevent unintended revocation when not using a token
with a long enough lifetime. To revoke these certificates, use the `sshca/revoke`
endpoint.

## Quick Start

#### Mount the backend

The first step to using the PKI backend is to mount it. Unlike the `generic`
backend, the `sshca` backend is not mounted by default.

```text
$ vault mount sshca
Successfully mounted 'sshca' at 'sshca'!
```

#### Configure a CA certificate

To configure the backend, an SSH key pair must be generated to serve as the CA key:

```text
$ ssh-keygen -N '' -f ./ca -C 'SSH CA key pair'
```

Now that we have the SSH CA key pair, these can be used to configure the SSH CA backend:

```text
$ cat ca | vault write sshca/config/ca private_key=- public_key="$(cat ca.pub | tr -d '\n')"
Success! Data written to: sshca/config/ca
```

Now that the SSH CA key pair is successfully saved in the backend, the `ca` and
`ca.pub` files should be deleted from your local machine.

#### Configure a role

The next step is to configure a role. A role is a logical name that maps to a
policy used to generate those credentials. For example, let's create an
"example" role:

```text
$ vault write sshca/roles/example ttl=4h
Success! Data written to: sshca/roles/example
```

#### Signing an SSH public key

By writing to the `roles/example` path we are defining the `example` role. To
sign an SSH public key, we simply write to the `sign` end point with that role
name: Vault is now configured to create and manage SSH certificates!

```text
$ cat ~/.ssh/id_rsa.pub | vault write sshca/sign/example public_key=- 
Key             Value
---             -----
lease_id        sshca/sign/example/3c3740ee-6066-55c0-4a5d-82a544a474a3
lease_duration  768h0m0s
lease_renewable false
serial_number   8343f840b8a027a7
signed_key      ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgxSlUi1Fd38w93emsotVQBjLYorkQTmCyRo0XPxJw/poAAAADAQABAAABAQCgbXubSftRY1JFEfFpkoHkf/4WkGNQr8g+X1H8kcU/UJUoFZl5IXaZrDzRUTUUQsC3bZA6EPerqSlgpy9gSYn/dtGcCCoPyOUQpaz3vRbF180ddzJnjaJvIAg1PHecFFLC+WjCPFeGkZPc5Yr1NyGhL5GiMUbv5fIYfSM5REkydcEn5+fryfZq8ZCSNBa0KfHflWvy9Nn3i3ns1ZphkMPp+DRkGw0Iy4VetfvUWd3bbVRP8PMZOz0o9Bo/90qzST3qBJ6DZip9LehBXfoNk3dvD/Rkst4IdjBLVv/gHnwX9V0yG8NMUCHh695S0anNtbjCFW1JedYXH7h5ayGOPfivg0P4QLigJ6cAAAABAAAABHJvb3QAAAAAAAAAAFhfuTMAAAAAWF/xkQAAAAAAAAAAAAAAAAAAARcAAAAHc3NoLXJzYQAAAAMBAAEAAAEBALiUMk0TnJh++UOYEU6LcsRAxTcZbR31XbbvtXBGLdK9P92ufZuSxvASVjEoHiJuI+a+rnw7q4GGwoBZQ4wooN/Az5Iy7ez04sz629UINQgUfHbp8RHVk3tCBrJ1F0aQKNEDz3LKNNuAF6kJZrXZ2d0pdCDorm0cNfaYZxOmyKAQtVH454xR2gP0VYUwOWcxTPF8lnoNecL6drEKxg0eyGl2dK+MndsE2TwE9b1S2LDatzfmVzVKQWL5JJWgNwGNiy65E0C858TLzQ7imrVqPomp3SppWLItMUNHZgy9uujyS3BeMqzLT6e1e+ndWMD92Ei2/t95JaSR9IMmClQS0BkAAAEPAAAAB3NzaC1yc2EAAAEAM4vtt9WhBtB98XfJsVo5TXI+XU6aAXm/yZH8wRpCl3ghhBDk5ZFdZredLna2v8jYELTNJGt8LuFZVy7XoXgsPC58kwhWcYx2BbtN3GpBDijlG7Odozwf03RrJ48LgheI9UfF+8mituwrerQDYppPgW5tws+THllhcWD099LU+iDvuC69aVEDy+CZJZKBvaYVDQYtu5bVlqdlGo5KE1ASro2h/jLQG2atl4iwpQ7NKi5VF5YuNFNX9NsWFIqnm5ErwXLdroBJb/XOSSWNE8Vlsi+UhNRJ33o3/QwQ3nMAjyxh1btnv2HW0r4Z3D4a63r+HizFP+RrGdRzNf7xj9UiRw==
```

## API

### /sshca/public_key
#### GET

<dl class="api">
  <dt>Description</dt>
  <dd>
    Retrieves the SSH CA public key.
    This is a bare endpoint that does not return a standard Vault data structure.<br />
    <br />This is an unauthenticated endpoint.
  </dd>

  <dt>Method</dt>
  <dd>GET</dd>

  <dt>URL</dt>
  <dd>`/sshca/public_key`</dd>

  <dt>Parameters</dt>
  <dd>
     None
  </dd>

  <dt>Returns</dt>
  <dd>

    ```
    <SSH CA public key>
    ```

  </dd>
</dl>

### /sshca/config/ca
#### POST

<dl class="api">
  <dt>Description</dt>
  <dd>
    Allows submitting the CA information for the backend via an SSH key pair.
    _If you have already set a certificate and key, they will be overridden._<br /><br />
  </dd>

  <dt>Method</dt>
  <dd>POST</dd>

  <dt>URL</dt>
  <dd>`/sshca/config/ca`</dd>

  <dt>Parameters</dt>
  <dd>
    <ul>
      <li>
        <span class="param">private_key</span>
        <span class="param-flags">required</span>
        The private key part the SSH CA key pair.
      </li>
      <li>
        <span class="param">public_key</span>
        <span class="param-flags">optional</span>
        The public key part of the SSH CA key pair. Note that this will not be validated
        and will be returned as-is by the `/sshca/public_key` endpoint.
      </li>
    </ul>
  </dd>

  <dt>Returns</dt>
  <dd>
    A `204` response code.
  </dd>
</dl>

### /sshca/crl
#### GET

<dl class="api">
  <dt>Description</dt>
  <dd>
    Retrieves the current CRL. This is a bare endpoint that does not return a
    standard Vault data structure.
    <br /><br />This is an unauthenticated endpoint.
  </dd>

  <dt>Method</dt>
  <dd>POST</dd>

  <dt>URL</dt>
  <dd>`/sshca/crl`</dd>

  <dt>Parameters</dt>
  <dd>
    None
  </dd>

  <dt>Returns</dt>
  <dd>
    
    ```
    <List of revoked SSH certificates>
    ```

  </dd>
</dl>

### /sshca/revoke
#### POST

<dl class="api">
  <dt>Description</dt>
  <dd>
    Revokes an SSH certificate using its serial number. This is an
    alternative option to the standard method of revoking
    using Vault lease IDs. A successful revocation will
    rotate the CRL.
  </dd>

  <dt>Method</dt>
  <dd>POST</dd>

  <dt>URL</dt>
  <dd>`/sshca/revoke`</dd>

  <dt>Parameters</dt>
  <dd>
    <ul>
      <li>
        <span class="param">serial_number</span>
        <span class="param-flags">required</span>
        The serial number of the SSH certificate to revoke.
      </li>
    </ul>
  </dd>

  <dt>Returns</dt>
  <dd>

    ```json
    {
      "data": {
        "revocation_time": 1433269787
      }
    }
    ```
  </dd>
</dl>

### /sshca/roles
#### POST

<dl class="api">
  <dt>Description</dt>
  <dd>
    Creates or updates the role definition.
  </dd>

  <dt>Method</dt>
  <dd>POST</dd>

  <dt>URL</dt>
  <dd>`/sshca/roles/<role name>`</dd>

  <dt>Parameters</dt>
  <dd>
    <ul>
      <li>
        <span class="param">ttl</span>
        <span class="param-flags">optional</span>
        The Time To Live value provided as a string duration with time suffix.
        Hour is the largest suffix.  If not set, uses the system default value
        or the value of `max_ttl`, whichever is shorter.
      </li>
      <li>
        <span class="param">max_ttl</span>
        <span class="param-flags">optional</span>
        The maximum Time To Live provided as a string duration with time
        suffix. Hour is the largest suffix. If not set, defaults to the system
        maximum lease TTL.
      </li>
      <li>
        <span class="param">allowed_critical_options</span>
        <span class="param-flags">optional</span>
        A comma-separated list of critical options that certificates can have when
        signed. To allow any critical options, set this to an empty string. Will
        default to allowing any critical options.
      </li>
      <li>
        <span class="param">allowed_extensions</span>
        <span class="param-flags">optional</span>
        A comma-separated list of extensions that certificates can have when
        signed. To allow any critical options, set this to an empty string. Will
        default to allowing any extensions.
      </li>
      <li>
        <span class="param">default_critical_options</span>
        <span class="param-flags">optional</span>
        A map of critical options certificates should have if none are provided
        when signing. Note that these are not restricted by
        `allowed_critical_options`. Defaults to none.
      </li>
      <li>
        <span class="param">default_extensions</span>
        <span class="param-flags">optional</span>
        A map of extensions certificates should have if none are provided
        when signing. Note that these are not restricted by
        `allowed_extensions`. Defaults to none.
      </li>
      <li>
        <span class="param">allow_user_certificates</span>
        <span class="param-flags">optional</span>
        If set, certificates are allowed to be signed for use as a 'user'.
        Defaults to true.
      </li>
      <li>
        <span class="param">allow_host_certificates</span>
        <span class="param-flags">optional</span>
        If set, certificates are allowed to be signed for use as a 'host'.
        Defaults to true.
      </li>
      <li>
        <span class="param">allowed_valid_principals</span>
        <span class="param-flags">optional</span>
        Comma separated list of valid principals that signing certificates can
        request a subset of or an empty string if any, including none, are
        valid. Treated as a list of domains for 'host' certificate types.
        Defaults to allowing any.
      </li>
      <li>
        <span class="param">allow_bare_domains</span>
        <span class="param-flags">optional</span>
        If set, host certificates that are requested are allowed to use the base
        domains listed in "allowed_valid_principals", e.g. "example.com". This
        is a separate option as in some cases this can be considered a security
        threat. Defaults to false.
      </li>
      <li>
        <span class="param">allow_subdomains</span>
        <span class="param-flags">optional</span>
        If set, host certificates that are requested are allowed to use
        subdomains of those listed in "allowed_valid_principals". Defaults
        to false.
      </li>
    </ul>
  </dd>

  <dt>Returns</dt>
  <dd>
    A `204` response code.
  </dd>
</dl>

#### GET

<dl class="api">
  <dt>Description</dt>
  <dd>
    Queries the role definition.
  </dd>

  <dt>Method</dt>
  <dd>GET</dd>

  <dt>URL</dt>
  <dd>`/sshca/roles/<role name>`</dd>

  <dt>Parameters</dt>
  <dd>
     None
  </dd>

  <dt>Returns</dt>
  <dd>

    ```json
    {
      "data": {
        "allow_bare_domains": false,
        "allow_host_certificates": true,
        "allow_subdomains": false,
        "allow_user_certificates": true,
        "allowed_critical_options": "",
        "allowed_extensions": "",
        "allowed_valid_principals": "",
        "default_critical_options": {},
        "default_extensions": {},
        "max_ttl": "768h",
        "ttl": "4h"
      }
    }
    ```

  </dd>
</dl>

#### LIST
<dl class="api">
  <dt>Description</dt>
  <dd>
    Returns a list of available roles. Only the role names are returned, not
    any values.
  </dd>

  <dt>Method</dt>
  <dd>LIST/GET</dd>

  <dt>URL</dt>
  <dd>`/sshca/roles` (LIST) or `/sshca/roles?list=true` (GET)</dd>

  <dt>Parameters</dt>
  <dd>
     None
  </dd>

  <dt>Returns</dt>
  <dd>

  ```json
  {
    "auth": null,
    "data": {
      "keys": ["dev", "prod"]
    },
    "lease_duration": 2764800,
    "lease_id": "",
    "renewable": false
  }
  ```

  </dd>
</dl>

#### DELETE
<dl class="api">
  <dt>Description</dt>
  <dd>
    Deletes the role definition. Deleting a role does <b>not</b> revoke
    certificates previously issued under this role.
  </dd>

  <dt>Method</dt>
  <dd>DELETE</dd>

  <dt>URL</dt>
  <dd>`/sshca/roles/<role name>`</dd>

  <dt>Parameters</dt>
  <dd>
     None
  </dd>

  <dt>Returns</dt>
  <dd>
    A `204` response code.
  </dd>
</dl>

### /sshca/sign
#### POST

<dl class="api">
  <dt>Description</dt>
  <dd>
    Signs an SSH public key based on the supplied parameters, subject to the
    restrictions contained in the role named in the endpoint.
  </dd>

  <dt>Method</dt>
  <dd>POST</dd>

  <dt>URL</dt>
  <dd>`/sshca/sign/<role name>`</dd>

  <dt>Parameters</dt>
  <dd>
    <ul>
      <li>
        <span class="param">public_key</span>
        <span class="param-flags">required</span>
        SSH public key that should be signed.
      </li>
      <li>
        <span class="param">ttl</span>
        <span class="param-flags">optional</span>
        Requested Time To Live. Cannot be greater than the role's `max_ttl`
        value. If not provided, the role's `ttl` value will be used. Note that
        the role values default to system values if not explicitly set.
      </li>
      <li>
        <span class="param">valid_principals</span>
        <span class="param-flags">optional</span>
        Valid principals, either usernames or hostnames, that the certificate
        should be signed for. Defaults to none.
      </li>
      <li>
        <span class="param">cert_type</span>
        <span class="param-flags">optional</span>
        Type of certificate to be created; either "user" or "host". Defaults to
        "user".
      </li>
      <li>
        <span class="param">key_id</span>
        <span class="param-flags">optional</span>
        Key id that the created certificate should have. If not specified,
        the display name of the token will be used.
      </li>
      <li>
        <span class="param">critical_options</span>
        <span class="param-flags">optional</span>
        A map of the critical options that the certificate should be signed for.
        Defaults to none.
      </li>
      <li>
        <span class="param">extensions</span>
        <span class="param-flags">optional</span>
        A map of the extensions that the certificate should be signed for.
        Defaults to none
      </li>
    </ul>
  </dd>

  <dt>Returns</dt>
  <dd>

    ```json
    {
      "lease_id": "sshca/sign/example/097bf207-96dd-0041-0e83-b23bd1923993",
      "renewable": false,
      "lease_duration": 21600,
      "data": {
        "serial_number": "f65ed2fd21443d5c",
        "signed_key": "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1y...\n"
        },
      "auth": null
    }
    ```

  </dd>
</dl>

### /sshca/tidy
#### POST

<dl class="api">
  <dt>Description</dt>
  <dd>
    Allows tidying up the backend storage and/or CRL by removing certificates
    that have expired and are past a certain buffer period beyond their
    expiration time.
  </dd>

  <dt>Method</dt>
  <dd>POST</dd>

  <dt>URL</dt>
  <dd>`/sshca/tidy`</dd>

  <dt>Parameters</dt>
  <dd>
    <ul>
      <li>
        <span class="param">tidy_cert_store</span>
        <span class="param-flags">optional</span>
        Whether to tidy up the certificate store. Defaults to `false`.
      </li>
      <li>
      <span class="param">tidy_revocation_list</span>
      <span class="param-flags">optional</span>
        Whether to tidy up the revocation list (CRL). Defaults to `false`.
      </li>
      <li>
      <span class="param">safety_buffer</span>
      <span class="param-flags">optional</span>
        A duration (given as an integer number of seconds or a string; defaults
        to `72h`) used as a safety buffer to ensure certificates are not
        expunged prematurely; as an example, this can keep certificates from
        being removed from the CRL that, due to clock skew, might still be
        considered valid on other hosts. For a certificate to be expunged, the
        time must be after the expiration time of the certificate (according to
        the local clock) plus the duration of `safety_buffer`.
      </li>
    </ul>
  </dd>

  <dt>Returns</dt>
  <dd>
    A `204` status code.
  </dd>
</dl>
