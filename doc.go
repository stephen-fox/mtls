// Package mtls provides functionality for creating TLS certificates for use in
// mutual authentication modes (e.g., client provides a certificate and both
// parties validate each others' certificates). The term 'certificate' refers
// to both the private key and the associated public certificate.
//
// This library is focused on providing tooling for creating certificates for
// use in mutual authentication modes. However, it may be used to generate
// certificates for use in standard TLS modes.
package mtls
