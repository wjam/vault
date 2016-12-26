package ssh

import (
	"fmt"
	"github.com/go-errors/errors"
	"github.com/hashicorp/vault/helper/errutil"
	"github.com/hashicorp/vault/logical"
	"strings"
	"time"
)

type sshCertificate struct {
	ValidBefore time.Time `json:"valid_before"`
	Certificate string    `json:"certificate"`
	Revocation  time.Time `json:"revocation"`
}

func revokeSSHCertificate(req *logical.Request, serialNumber string) (*logical.Response, error) {

	existing, err := req.Storage.Get("revoked/" + serialNumber)
	if err != nil {
		return nil, err
	}

	if existing != nil {
		var revokedCertificate sshCertificate
		if err := existing.DecodeJSON(&revokedCertificate); err != nil {
			return nil, errutil.InternalError{Err: fmt.Sprintf("Unable to decode existing entry for SSH certificate serial %s", serialNumber)}
		}

		return revokedCertificate.toRevokedResponse(), nil
	}

	entry, err := req.Storage.Get("certs/" + serialNumber)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("Unnknown certificate serial number '%v'", serialNumber)
	}

	var revokedCertificate sshCertificate
	if err := entry.DecodeJSON(&revokedCertificate); err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("Unable to decode entry for SSH certificate serial %s", serialNumber)}
	}

	revokedCertificate.Revocation = time.Now().UTC()

	revokedEntry, err := logical.StorageEntryJSON("revoked/"+serialNumber, revokedCertificate)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(revokedEntry); err != nil {
		return nil, errors.New("Error saving revoked certificate to new location")
	}

	if err := buildCrl(req); err != nil {
		return nil, err
	}

	return revokedCertificate.toRevokedResponse(), nil
}

func buildCrl(req *logical.Request) error {
	revokedSerials, err := req.Storage.List("revoked/")
	if err != nil {
		return errutil.InternalError{Err: fmt.Sprintf("Error fetching list of revoked SSH certs: %s", err)}
	}

	revokedCertificates := []string{}
	for _, serial := range revokedSerials {
		revokedEntry, err := req.Storage.Get("revoked/" + serial)
		if err != nil {
			return errutil.InternalError{Err: fmt.Sprintf("Unable to fetch revoked SSH cert with serial %s: %s", serial, err)}
		}
		if revokedEntry == nil {
			return errutil.InternalError{Err: fmt.Sprintf("Revoked SSH certificate entry for serial %s is nil", serial)}
		}

		var revokedCertificate sshCertificate
		err = revokedEntry.DecodeJSON(&revokedCertificate)
		if err != nil {
			return errutil.InternalError{Err: fmt.Sprintf("Unable to decode entry for SSH certificate serial %s", serial)}
		}

		revokedCertificates = append(revokedCertificates, revokedCertificate.Certificate)
	}

	err = req.Storage.Put(&logical.StorageEntry{
		Key:   "crl",
		Value: []byte(strings.Join(revokedCertificates, "\n")),
	})
	if err != nil {
		return errutil.InternalError{Err: fmt.Sprintf("Error storing CRL: %s", err)}
	}

	return nil
}

func (c *sshCertificate) toRevokedResponse() *logical.Response {
	return &logical.Response{
		Data: map[string]interface{}{
			"revocation_time":         c.Revocation.Unix(),
			"revocation_time_rfc3339": c.Revocation.Format(time.RFC3339Nano),
		},
	}
}
