package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	httpClient := &http.Client{}

	certificatePath := "./certificate.crt"
	privateKeyPath := "./private-key.pem"

	cert, err := tls.LoadX509KeyPair(certificatePath, privateKeyPath)
	if err != nil {
		log.Fatal(err.Error())
	}

	caCert, err := ioutil.ReadFile(certificatePath)
	if err != nil {
		log.Fatal(err.Error())
	}
	caCertPool := x509.NewCertPool()

	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatal("Failed to append certificate to pool")
	}

	mTlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	mTlsConfig.BuildNameToCertificate()

	httpTransport := &http.Transport{
		TLSClientConfig: mTlsConfig,
	}

	httpClient.Transport = httpTransport

	// Do things with the 'httpClient'.
}
