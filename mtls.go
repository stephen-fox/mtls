package mtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"time"
)

// BasicBuilder is a very basic mutual TLS certificate builder.
type BasicBuilder struct {
	TemplateCert   *x509.Certificate
	ParentIfNotCa  *x509.Certificate
	PrivateKey     crypto.Signer
	Entropy        io.Reader
	GenerateSerial bool
}

// BuildPemBlocks will build the certificate in the form of PEM blocks.
func (o *BasicBuilder) BuildPemBlocks() (*PemBlocks, error) {
	if o.TemplateCert == nil {
		return nil, fmt.Errorf("template certificate cannot be nil")
	}

	if o.Entropy == nil {
		return nil, fmt.Errorf("entropy cannot be nil")
	}

	if o.GenerateSerial {
		serial, err := serialNumber(o.Entropy)
		if err != nil {
			return nil, err
		}

		o.TemplateCert.SerialNumber = serial
	}

	var parent *x509.Certificate
	if o.TemplateCert.IsCA {
		parent = o.TemplateCert
	} else if o.ParentIfNotCa != nil {
		parent = o.ParentIfNotCa
	} else {
		return nil, fmt.Errorf("template certificate is not a CA and a parent certificate was not provided")
	}

	certRaw, err := x509.CreateCertificate(o.Entropy, o.TemplateCert, parent, o.PrivateKey.Public(), o.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate from template - %s", err.Error())
	}

	keyBlock, err := privateKeyPemBlock(o.PrivateKey)
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

// CreateFiles creates a certificate and private key pair for TLS mutual
// authentication at the specified locations. If the specified files already
// exist, then they will be overwritten. Domain names and IP addresses are
// optional. If you do not wish to specify one or the other, simply set the
// value to nil or to an empty list.
func CreateFiles(organizationNames []string, optionalIps []net.IP, optionalDomainNames []string, expiration time.Time, privateKeyOutPath string, certOutPath string) error {
	keyOut, err := os.OpenFile(privateKeyOutPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return errors.New("Failed to create private key file - " + err.Error())
	}
	defer keyOut.Close()

	certOut, err := os.Create(certOutPath)
	if err != nil {
		os.Remove(privateKeyOutPath)
		return errors.New("Failed to create certificate file - " + err.Error())
	}
	defer certOut.Close()

	certificate, privateKey, err := CreateBlocks(organizationNames, optionalIps, optionalDomainNames, expiration)
	if err != nil {
		os.Remove(certOutPath)
		os.Remove(privateKeyOutPath)
		return err
	}

	err = pem.Encode(certOut, certificate)
	if err != nil {
		os.Remove(certOutPath)
		os.Remove(privateKeyOutPath)
		return errors.New("Failed to encode certificate - " + err.Error())
	}

	err = pem.Encode(keyOut, privateKey)
	if err != nil {
		os.Remove(certOutPath)
		os.Remove(privateKeyOutPath)
		return errors.New("Failed to encode private key - " + err.Error())
	}

	return nil
}

// CreateBlocks creates a certificate and private key pair for TLS mutual
// authentication in the block format. Domain names and IP addresses are
// optional. If you do not wish to specify one or the other, simply set the
// value to nil or to an empty list.
func CreateBlocks(organizationNames []string, optionalIps []net.IP, optionalDomainNames []string, expiration time.Time) (certificate *pem.Block, privateKey *pem.Block, err error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return certificate, privateKey, errors.New("Failed to generate serial number - " + err.Error())
	}

	template := x509.Certificate{
		Subject: pkix.Name{
			Organization: organizationNames,
		},
		SerialNumber:          serialNumber,
		NotBefore:             time.Now(),
		NotAfter:              expiration,
		BasicConstraintsValid: true,
		IsCA: true,
	}

	if optionalDomainNames != nil && len(optionalDomainNames) > 0 {
		template.DNSNames = optionalDomainNames
	}

	if optionalIps != nil && len(optionalIps) > 0 {
		template.IPAddresses = optionalIps
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return certificate, privateKey, errors.New("Failed to generate private key - " + err.Error())
	}

	certRaw, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return certificate, privateKey, errors.New("Failed to generate certificate - " + err.Error())
	}

	certificate = &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certRaw,
	}

	privateKey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	return certificate, privateKey, nil
}

func serialNumber(entropy io.Reader) (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(entropy, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number - %s", err.Error())
	}

	return serialNumber, nil
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
