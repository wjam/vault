package sshca

import (
	"testing"

	"encoding/base64"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/logical"
	logicaltest "github.com/hashicorp/vault/logical/testing"
	"golang.org/x/crypto/ssh"
	"reflect"
	"strings"
	"time"
)

func TestBackend_TidyRemovesOldCertificates(t *testing.T) {

	storage := &logical.InmemStorage{}
	config := logical.TestBackendConfig()
	config.StorageView = storage

	b, err := Factory(config)
	if err != nil {
		t.Fatalf("Cannot create backend: %s", err)
	}

	validCertificate, err := logical.StorageEntryJSON("certs/valid-certificate", sshCertificate{
		Certificate: "",
		ValidBefore: time.Now().Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Unable to save data %v", err)
	}
	if err := storage.Put(validCertificate); err != nil {
		t.Fatalf("Unable to save data %v", err)
	}

	expiredCertificate, err := logical.StorageEntryJSON("certs/expired-certificate", sshCertificate{
		Certificate: "",
		ValidBefore: time.Now().Add(-30 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Unable to save data %v", err)
	}
	if err := storage.Put(expiredCertificate); err != nil {
		t.Fatalf("Unable to save data %v", err)
	}

	validRevoked, err := logical.StorageEntryJSON("revoked/valid-revoked", sshCertificate{
		Certificate: "",
		ValidBefore: time.Now().Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Unable to save data %v", err)
	}
	if err := storage.Put(validRevoked); err != nil {
		t.Fatalf("Unable to save data %v", err)
	}

	expiredRevoked, err := logical.StorageEntryJSON("revoked/revoked-expired", sshCertificate{
		Certificate: "",
		ValidBefore: time.Now().Add(-30 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Unable to save data %v", err)
	}
	if err := storage.Put(expiredRevoked); err != nil {
		t.Fatalf("Unable to save data %v", err)
	}

	req := logical.TestRequest(t, logical.UpdateOperation, "tidy")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"tidy_revocation_list": true,
		"tidy_cert_store":      true,
		"safety_buffer":        "15m",
	}
	_, err = b.HandleRequest(req)
	if err != nil {
		t.Fatalf("Tidy request failed %v", err)
	}

	certs, err := config.StorageView.List("certs/")
	if err != nil {
		t.Fatalf("Unable to list certificates: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("Valid certificates after tidy is too many: %v", certs)
	}
	if "valid-certificate" != certs[0] {
		t.Fatalf("Unexpected valid certificate. Exptedted %v, actual %v", "valid-certificate", certs[0])
	}

	revoked, err := config.StorageView.List("revoked/")
	if err != nil {
		t.Fatalf("Unable to list revoked certificates: %v", err)
	}
	if len(revoked) != 1 {
		t.Fatalf("Revoked certificates after tidy is too many: %v", revoked)
	}
	if "valid-revoked" != revoked[0] {
		t.Fatalf("Unexpected revoked certificate. Exptedted %v, actual %v", "valid-certificate", revoked[0])
	}

}

func TestBackend_AbleToRetrievePublicKey(t *testing.T) {

	config := logical.TestBackendConfig()

	b, err := Factory(config)
	if err != nil {
		t.Fatalf("Cannot create backend: %s", err)
	}

	testCase := logicaltest.TestCase{
		Backend: b,
		Steps: []logicaltest.TestStep{
			configCaStep(),

			logicaltest.TestStep{
				Operation:       logical.ReadOperation,
				Path:            "public_key",
				Unauthenticated: true,

				Check: func(resp *logical.Response) error {

					key := string(resp.Data["http_raw_body"].([]byte))

					if key != publicKey {
						return fmt.Errorf("public_key incorrect. Expected %v, actual %v", publicKey, key)
					}

					return nil
				},
			},
		},
	}

	logicaltest.Test(t, testCase)
}

func TestBackend_ValidPrincipalsValidatedForHostCertificates(t *testing.T) {
	config := logical.TestBackendConfig()

	b, err := Factory(config)
	if err != nil {
		t.Fatalf("Cannot create backend: %s", err)
	}

	testCase := logicaltest.TestCase{
		Backend: b,
		Steps: []logicaltest.TestStep{
			configCaStep(),

			createRoleStep("testing", map[string]interface{}{
				"allowed_valid_principals": "example.com,example.org",
				"allow_subdomains":         true,
				"default_critical_options": map[string]interface{}{
					"option": "value",
				},
				"default_extensions": map[string]interface{}{
					"extension": "extended",
				},
			}),

			signCertificateStep("testing", "root", ssh.HostCert, []string{"dummy.example.org", "second.example.com"}, map[string]string{
				"option": "value",
			}, map[string]string{
				"extension": "extended",
			},
				2*time.Hour, map[string]interface{}{
					"public_key":       publicKey2,
					"ttl":              "2h",
					"cert_type":        "host",
					"valid_principals": "dummy.example.org,second.example.com",
				}),
		},
	}

	logicaltest.Test(t, testCase)
}

func TestBackend_OptionsOverrideDefaults(t *testing.T) {
	config := logical.TestBackendConfig()

	b, err := Factory(config)
	if err != nil {
		t.Fatalf("Cannot create backend: %s", err)
	}

	testCase := logicaltest.TestCase{
		Backend: b,
		Steps: []logicaltest.TestStep{
			configCaStep(),

			createRoleStep("testing", map[string]interface{}{
				"allowed_critical_options": "option,secondary",
				"allowed_extensions":       "extension,additional",
				"default_critical_options": map[string]interface{}{
					"option": "value",
				},
				"default_extensions": map[string]interface{}{
					"extension": "extended",
				},
			}),

			signCertificateStep("testing", "root", ssh.UserCert, nil, map[string]string{
				"secondary": "value",
			}, map[string]string{
				"additional": "value",
			}, 2*time.Hour, map[string]interface{}{
				"public_key": publicKey2,
				"ttl":        "2h",
				"critical_options": map[string]interface{}{
					"secondary": "value",
				},
				"extensions": map[string]interface{}{
					"additional": "value",
				},
			}),
		},
	}

	logicaltest.Test(t, testCase)
}

func TestBackend_RevokedCertificatesAppearOnCRL(t *testing.T) {
	config := logical.TestBackendConfig()

	b, err := Factory(config)
	if err != nil {
		t.Fatalf("Cannot create backend: %s", err)
	}

	var serialNumber, signedKey string

	testCase := logicaltest.TestCase{
		Backend: b,
		Steps: []logicaltest.TestStep{
			configCaStep(),

			logicaltest.TestStep{
				Operation:       logical.ReadOperation,
				Path:            "crl",
				Unauthenticated: true,

				Check: func(resp *logical.Response) error {

					crl := string(resp.Data["http_raw_body"].([]byte))

					if crl != "" {
						return fmt.Errorf("CRL already contains revoked certificates: %s", crl)
					}

					return nil
				},
			},

			createRoleStep("testing", map[string]interface{}{
				"allowed_valid_principals": "dummy",
			}),

			logicaltest.TestStep{
				Operation: logical.UpdateOperation,
				Path:      "sign/testing",
				Data: map[string]interface{}{
					"public_key":       publicKey,
					"key_id":           "foo-bar",
					"valid_principals": "dummy",
				},

				Check: func(resp *logical.Response) error {

					serialNumber = resp.Data["serial_number"].(string)
					if serialNumber == "" {
						return errors.New("No serial number in response")
					}

					signedKey = strings.TrimSpace(resp.Data["signed_key"].(string))
					if signedKey == "" {
						return errors.New("No signed key in response")
					}

					key, _ := base64.StdEncoding.DecodeString(strings.Split(signedKey, " ")[1])

					parsedKey, err := ssh.ParsePublicKey(key)
					if err != nil {
						return err
					}

					return validateSSHCertificate(parsedKey.(*ssh.Certificate), "foo-bar", ssh.UserCert, []string{"dummy"}, map[string]string{}, map[string]string{}, 24*time.Hour)
				},
			},

			logicaltest.TestStep{
				Operation: logical.UpdateOperation,
				Path:      "revoke",
				PreFlight: func(req *logical.Request) error {
					req.Data = map[string]interface{}{
						"serial_number": serialNumber,
					}
					return nil
				},

				Check: func(resp *logical.Response) error {

					revocationTime := resp.Data["revocation_time_rfc3339"].(string)

					if revocationTime == "" {
						return errors.New("Blank revocation time")
					}

					return nil
				},
			},

			logicaltest.TestStep{
				Operation: logical.ReadOperation,
				Path:      "crl",

				Check: func(resp *logical.Response) error {

					crl := string(resp.Data["http_raw_body"].([]byte))

					revokedCertificates := strings.Split(crl, "\n")

					for _, revoked := range revokedCertificates {
						if revoked == signedKey {
							return nil
						}
					}

					return fmt.Errorf("Revoked certificates did not contain expected certificate. Expected: '%v', Actual: '%v'", signedKey, revokedCertificates)
				},
			},
		},
	}

	logicaltest.Test(t, testCase)
}

func configCaStep() logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "config/ca",
		Data: map[string]interface{}{
			"public_key":  publicKey,
			"private_key": privateKey,
		},
	}
}

func createRoleStep(name string, parameters map[string]interface{}) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.CreateOperation,
		Path:      "roles/" + name,
		Data:      parameters,
	}
}

func signCertificateStep(role, keyId string, certType int, validPrincipals []string, criticalOptionPermissions, extensionPermissions map[string]string, ttl time.Duration,
	requestParameters map[string]interface{}) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "sign/" + role,
		Data:      requestParameters,

		Check: func(resp *logical.Response) error {

			serialNumber := resp.Data["serial_number"].(string)
			if serialNumber == "" {
				return errors.New("No serial number in response")
			}

			signedKey := strings.TrimSpace(resp.Data["signed_key"].(string))
			if signedKey == "" {
				return errors.New("No signed key in response")
			}

			key, _ := base64.StdEncoding.DecodeString(strings.Split(signedKey, " ")[1])

			parsedKey, err := ssh.ParsePublicKey(key)
			if err != nil {
				return err
			}

			return validateSSHCertificate(parsedKey.(*ssh.Certificate), keyId, certType, validPrincipals, criticalOptionPermissions, extensionPermissions, ttl)
		},
	}
}

func validateSSHCertificate(cert *ssh.Certificate, keyId string, certType int, validPrincipals []string, criticalOptionPermissions, extensionPermissions map[string]string,
	ttl time.Duration) error {

	if cert.KeyId != keyId {
		return fmt.Errorf("Incorrect KeyId: %v", cert.KeyId)
	}

	if cert.CertType != uint32(certType) {
		return fmt.Errorf("Incorrect CertType: %v", cert.CertType)
	}

	if time.Unix(int64(cert.ValidAfter), 0).After(time.Now()) {
		return fmt.Errorf("Incorrect ValidAfter: %v", cert.ValidAfter)
	}

	if time.Unix(int64(cert.ValidBefore), 0).Before(time.Now()) {
		return fmt.Errorf("Incorrect ValidBefore: %v", cert.ValidBefore)
	}

	actualTtl := time.Unix(int64(cert.ValidBefore), 0).Add(-30 * time.Second).Sub(time.Unix(int64(cert.ValidAfter), 0))
	if actualTtl != ttl {
		return fmt.Errorf("Incorrect ttl: expected: %v, actualL %v", ttl, actualTtl)
	}

	if !reflect.DeepEqual(cert.ValidPrincipals, validPrincipals) {
		return fmt.Errorf("Incorrect ValidPrincipals: expected: %#v actual: %#v", validPrincipals, cert.ValidPrincipals)
	}

	publicSigningKey, err := getSigningPublicKey()
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(cert.SignatureKey, publicSigningKey) {
		return fmt.Errorf("Incorrect SignatureKey: %v", cert.SignatureKey)
	}

	if cert.Signature == nil {
		return fmt.Errorf("Incorrect Signature: %v", cert.Signature)
	}

	if !reflect.DeepEqual(cert.Permissions.Extensions, extensionPermissions) {
		return fmt.Errorf("Incorrect Permissions.Extensions: Expected: %v, Actual: %v", extensionPermissions, cert.Permissions.Extensions)
	}

	if !reflect.DeepEqual(cert.Permissions.CriticalOptions, criticalOptionPermissions) {
		return fmt.Errorf("Incorrect Permissions.CriticalOptions: %v", cert.Permissions.CriticalOptions)
	}

	return nil
}

func getSigningPublicKey() (ssh.PublicKey, error) {
	key, err := base64.StdEncoding.DecodeString(strings.Split(publicKey, " ")[1])
	if err != nil {
		return nil, err
	}

	parsedKey, err := ssh.ParsePublicKey(key)
	if err != nil {
		return nil, err
	}

	return parsedKey, nil
}

const publicKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDArgK0ilRRfk8E7HIsjz5l3BuxmwpDd8DHRCVfOhbZ4gOSVxjEOOqBwWGjygdboBIZwFXmwDlU6sWX0hBJAgpQz0Cjvbjxtq/NjkvATrYPgnrXUhTaEn2eQO0PsqRNSFH46SK/oJfTp0q8/WgojxWJ2L7FUV8PO8uIk49DzqAqPV7WXU63vFsjx+3WQOX/ILeQvHCvaqs3dWjjzEoDudRWCOdUqcHEOshV9azIzPrXlQVzRV3QAKl6u7pC+/Secorpwt6IHpMKoVPGiR0tMMuNOVH8zrAKzIxPGfy2WmNDpJopbXMTvSOGAqNcp49O4SKOQl9Fzfq2HEevJamKLrMB dummy@example.com
`
const publicKey2 = `AAAAB3NzaC1yc2EAAAADAQABAAABAQDArgK0ilRRfk8E7HIsjz5l3BuxmwpDd8DHRCVfOhbZ4gOSVxjEOOqBwWGjygdboBIZwFXmwDlU6sWX0hBJAgpQz0Cjvbjxtq/NjkvATrYPgnrXUhTaEn2eQO0PsqRNSFH46SK/oJfTp0q8/WgojxWJ2L7FUV8PO8uIk49DzqAqPV7WXU63vFsjx+3WQOX/ILeQvHCvaqs3dWjjzEoDudRWCOdUqcHEOshV9azIzPrXlQVzRV3QAKl6u7pC+/Secorpwt6IHpMKoVPGiR0tMMuNOVH8zrAKzIxPGfy2WmNDpJopbXMTvSOGAqNcp49O4SKOQl9Fzfq2HEevJamKLrMB
`
const privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwK4CtIpUUX5PBOxyLI8+ZdwbsZsKQ3fAx0QlXzoW2eIDklcY
xDjqgcFho8oHW6ASGcBV5sA5VOrFl9IQSQIKUM9Ao7248bavzY5LwE62D4J611IU
2hJ9nkDtD7KkTUhR+Okiv6CX06dKvP1oKI8Vidi+xVFfDzvLiJOPQ86gKj1e1l1O
t7xbI8ft1kDl/yC3kLxwr2qrN3Vo48xKA7nUVgjnVKnBxDrIVfWsyMz615UFc0Vd
0ACperu6Qvv0nnKK6cLeiB6TCqFTxokdLTDLjTlR/M6wCsyMTxn8tlpjQ6SaKW1z
E70jhgKjXKePTuEijkJfRc36thxHryWpii6zAQIDAQABAoIBAA/DrPD8iF2KigiL
F+RRa/eFhLaJStOuTpV/G9eotwnolgY5Hguf5H/tRIHUG7oBZLm6pMyWWZp7AuOj
CjYO9q0Z5939vc349nVI+SWoyviF4msPiik1bhWulja8lPjFu/8zg+ZNy15Dx7ei
vAzleAupMiKOv8pNSB/KguQ3WZ9a9bcQcoFQ2Foru6mXpLJ03kghVRlkqvQ7t5cA
n11d2Hiipq9mleESr0c+MUPKLBX/neaWfGA4xgJTjIYjZi6avmYc/Ox3sQ9aLq2J
tH0D4HVUZvaU28hn+jhbs64rRFbu++qQMe3vNvi/Q/iqcYU4b6tgDNzm/JFRTS/W
njiz4mkCgYEA44CnQVmonN6qQ0AgNNlBY5+RX3wwBJZ1AaxpzwDRylAt2vlVUA0n
YY4RW4J4+RMRKwHwjxK5RRmHjsIJx+nrpqihW3fte3ev5F2A9Wha4dzzEHxBY6IL
362T/x2f+vYk6tV+uTZSUPHsuELH26mitbBVFNB/00nbMNdEc2bO5FMCgYEA2NCw
ubt+g2bRkkT/Qf8gIM8ZDpZbARt6onqxVcWkQFT16ZjbsBWUrH1Xi7alv9+lwYLJ
ckY/XDX4KeU19HabeAbpyy6G9Q2uBSWZlJbjl7QNhdLeuzV82U1/r8fy6Uu3gQnU
WSFx2GesRpSmZpqNKMs5ksqteZ9Yjg1EIgXdINsCgYBIn9REt1NtKGOf7kOZu1T1
cYXdvm4xuLoHW7u3OiK+e9P3mCqU0G4m5UxDMyZdFKohWZAqjCaamWi9uNGYgOMa
I7DG20TzaiS7OOIm9TY17eul8pSJMrypnealxRZB7fug/6Bhjaa/cktIEwFr7P4l
E/JFH73+fBA9yipu0H3xQwKBgHmiwrLAZF6VrVcxDD9bQQwHA5iyc4Wwg+Fpkdl7
0wUgZQHTdtRXlxwaCaZhJqX5c4WXuSo6DMvPn1TpuZZXgCsbPch2ZtJOBWXvzTSW
XkK6iaedQMWoYU2L8+mK9FU73EwxVodWgwcUSosiVCRV6oGLWdZnjGEiK00uVh38
Si1nAoGBAL47wWinv1cDTnh5mm0mybz3oI2a6V9aIYCloQ/EFcvtahyR/gyB8qNF
lObH9Faf0WGdnACZvTz22U9gWhw79S0SpDV31tC5Kl8dXHFiZ09vYUKkYmSd/kms
SeKWrUkryx46LVf6NMhkyYmRqCEjBwfOozzezi5WbiJy6nn54GQt
-----END RSA PRIVATE KEY-----
`
