package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/stephen-fox/mtls"
)

const (
	listenAddress     = "127.0.0.1"
	fullListenAddress = listenAddress + ":8888"
	testUri           = "/test"
)

func main() {
	log.Println("Creating mTLS pair...")

	cert, err := ioutil.TempFile("", "certificate-")
	if err != nil {
		log.Fatal("Failed to create temporary certificate file - ", err.Error())
	}
	defer cert.Close()
	defer os.Remove(cert.Name())

	privateKey, err := ioutil.TempFile("", "private-key-")
	if err != nil {
		log.Fatal("Failed to create temporary private key file - ", err.Error())
	}
	defer privateKey.Close()
	defer os.Remove(privateKey.Name())

	organizationNames := []string{
		"Junk, Inc.",
	}

	ips := []net.IP{
		net.ParseIP(listenAddress),
	}

	expiration := time.Now().Add(24 * time.Hour)

	err = mtls.CreateFiles(organizationNames, ips, nil, expiration, privateKey.Name(), cert.Name())
	if err != nil {
		log.Fatal(err.Error())
	}

	log.Println("Created mTLS pair at", cert.Name(), "and", privateKey.Name())

	caCert, err := ioutil.ReadFile(cert.Name())
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	mTlsConfig := &tls.Config{
		RootCAs:    caCertPool,
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	mTlsConfig.BuildNameToCertificate()

	server := &http.Server{
		Addr:      fullListenAddress,
		TLSConfig: mTlsConfig,
	}

	http.HandleFunc(testUri, printHelloWorld)

	log.Println("Ready for HTTP GET at 'https://" + fullListenAddress + testUri + "'")

	err = server.ListenAndServeTLS(cert.Name(), privateKey.Name())
	if err != nil {
		log.Fatal(err)
	}
}

func printHelloWorld(w http.ResponseWriter, r *http.Request) {
	log.Println("Hello world called")
	w.Write([]byte("hello world\n"))
}
