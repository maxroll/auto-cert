package util

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"sort"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/maxroll/auto-cert/pkg/requestor"
)

type CertificateBundle struct {
	Certificate []byte
	CaBundle    []byte
}

func CertToPEM(cert *x509.Certificate) []byte {
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	return pemCert
}

func StringSlicesEqual(a, b []string) bool {

	// sort first
	sort.Strings(a)
	sort.Strings(b)

	if len(a) != len(b) {
		log.Println("len")
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func SplitCerts(cert *requestor.Certificate) (*CertificateBundle, error) {

	certificates, err := certcrypto.ParsePEMBundle(cert.Certificate)
	if err != nil {
		return nil, err
	}

	certificate := CertToPEM(certificates[0])
	var bundle []byte

	for i, c := range certificates {
		if i > 0 {
			bundle = append(bundle, CertToPEM(c)...)
		}
	}

	return &CertificateBundle{certificate, bundle}, nil
}
