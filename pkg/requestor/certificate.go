package requestor

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/go-acme/lego/v4/certcrypto"
)

type Certificate struct {
	Certificate []byte
	PrivateKey  []byte
}

func GetPrivateKeyBytes(privateKey crypto.PrivateKey) []byte {
	pemKey := certcrypto.PEMBlock(privateKey)
	keyBytes := pem.EncodeToMemory(pemKey)
	return keyBytes
}

func LoadPrivateKey(keyBytes []byte) (crypto.PrivateKey, error) {
	keyBlock, _ := pem.Decode(keyBytes)

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	}

	return nil, errors.New("unknown private key type")
}
