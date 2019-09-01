package mtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
)

// BasicBuilder is a very basic TLS certificate builder. This is used to
// generate certificates for mutual authentication.
type BasicBuilder struct {
	// Template represents the certificate before it is built.
	Template *x509.Certificate

	// Parent is the parent (e.g., Certificate Authority) that will
	// issue the certificate. This can be nil if the Template is
	// a CA.
	Parent *x509.Certificate

	// KeyPair is the public-private key pair uniquely associated
	// with the Template.
	//
	// This can be generated using the "GenerateKey" functions found
	// in the 'ecdsa' and the 'rsa' packages. These functions will
	// generate a private key. The crypto.PublicKey can be extracted
	// from the private key structure.
	KeyPair crypto.Signer

	// Signer is the private key used to sign the Template. This is
	// required when the Template is being issued by a CA.
	Signer crypto.Signer

	// Entropy is the source of entropy used when building
	// the certificate.
	Entropy io.Reader

	// GenerateSerial, when true, will generate a new serial number
	// for the certificate at build time.
	GenerateSerial bool
}

// BuildPemBlocks will build the certificate in the form of PEM blocks.
func (o *BasicBuilder) BuildPemBlocks() (*PemBlocks, error) {
	if o.Template == nil {
		return nil, fmt.Errorf("template certificate cannot be nil")
	}

	if o.KeyPair == nil {
		return nil, fmt.Errorf("template key pair cannot be nil")
	}

	if o.Entropy == nil {
		return nil, fmt.Errorf("entropy cannot be nil")
	}

	if o.GenerateSerial {
		serial, err := serialNumber(o.Entropy)
		if err != nil {
			return nil, err
		}

		o.Template.SerialNumber = serial
	}

	var parent *x509.Certificate

	if o.Template.IsCA {
		parent = o.Template
	} else if o.Parent != nil {
		parent = o.Parent
		if o.Signer == nil {
			return nil, fmt.Errorf("signer cannot be nil when the template is being signed by a parent")
		}
	} else {
		return nil, fmt.Errorf("template certificate is not a CA and a parent certificate was not provided")
	}

	certRaw, err := x509.CreateCertificate(o.Entropy, o.Template, parent, o.KeyPair.Public(), o.Signer)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate from template - %s", err.Error())
	}

	keyBlock, err := privateKeyPemBlock(o.KeyPair)
	if err != nil {
		return nil, err
	}

	return &PemBlocks{
		Certificate: &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certRaw,
		},
		PrivateKey: keyBlock,
	}, nil
}

type PemBlocks struct {
	Certificate *pem.Block
	PrivateKey  *pem.Block
}

func serialNumber(entropy io.Reader) (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	sn, err := rand.Int(entropy, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number - %s", err.Error())
	}

	// If the first byte is greater than 127, then we have the wrong bits.
	if sn.Bytes()[0] > 127 {
		return serialNumber(entropy)
	}

	return sn, nil
}

func privateKeyPemBlock(privateKey crypto.Signer) (*pem.Block, error) {
	switch typedKey := privateKey.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(typedKey),
		}, nil
	case *ecdsa.PrivateKey:
		ecdsaRaw, err := x509.MarshalECPrivateKey(typedKey)
		if err != nil {
			return nil, err
		}
		return &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: ecdsaRaw,
		}, nil
	case nil:
		return nil, fmt.Errorf("private key cannot be nil")
	}

	return nil, fmt.Errorf("unsupported private key type")
}
