package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/stephen-fox/mtls"
)

const (
	applicationName = "mtls"

	organizationNamesCsvArg = "o"
	ipAddressesCsvArg       = "i"
	domainNamesCsvArg       = "d"
	certificatePathArg      = "c"
	privateKeyPathArg       = "p"
	validHoursArg           = "l"
	shouldPrintHelpArg      = "h"
	shouldPrintVersionArg   = "v"
	shouldPrintExamplesArg  = "x"

	examples = `	Generate a mTLS pair for organization 'Junk, Inc.' on loopback:
	` + applicationName + ` -` + organizationNamesCsvArg + ` 'Junk, Inc.' -` + ipAddressesCsvArg + ` 127.0.0.1

	` + `Generate a mTLS pair that supports several organizations on loopback:
	` + applicationName + ` -` + organizationNamesCsvArg + ` 'Junk, Inc.|Better Junk LLC.' -` + ipAddressesCsvArg + ` 127.0.0.1
	
	` + `Generate a mTLS pair for mycoolsite.com:
	` + applicationName + ` -` + organizationNamesCsvArg + ` 'Junk, Inc.' -` + domainNamesCsvArg + ` mycoolsite.com

	` + `Generate a mTLS pair that supports several DNS addresses:
	` + applicationName + ` -` + organizationNamesCsvArg + ` 'Junk, Inc.' -` + domainNamesCsvArg + ` mycoolsite.com,anothersite.net

	` + `Generate a mTLS pair that expires in 1 year:
	` + applicationName + ` -` + organizationNamesCsvArg + ` 'Junk, Inc.' -` + domainNamesCsvArg + ` mycoolsite.com` + ` -` + validHoursArg + ` 8760h
	
	` + `Generate a mTLS pair using custom paths and filenames:
	` + applicationName + ` -` + organizationNamesCsvArg + ` 'Junk, Inc.' -` + domainNamesCsvArg + ` mycoolsite.com -` + certificatePathArg + ` /tmp/cert.crt -` + privateKeyPathArg + ` /tmp/key.pem`
)

var (
	version string

	certificatePath      = flag.String(certificatePathArg, "./certificate.crt", "The path to create the certificate file")
	privateKeyPath       = flag.String(privateKeyPathArg, "./private-key.pem", "The path to create the private key file")
	organizationNamesCsv = flag.String(organizationNamesCsvArg, "", "The organization name(s) for the certificate (separated by '|')")
	ipAddressesCsv       = flag.String(ipAddressesCsvArg, "", "The IP address(es) for the certificate (separated by ',')")
	domainNamesCsv       = flag.String(domainNamesCsvArg, "", "The domain name(s) for the certificate (separated by ',')")
	validHours           = flag.Duration(validHoursArg, 24*time.Hour, "The duration for the certificate to remain valid for")

	shouldPrintVersion  = flag.Bool(shouldPrintVersionArg, false, "Print the application version")
	shouldPrintHelp     = flag.Bool(shouldPrintHelpArg, false, "Print this help page")
	shouldPrintExamples = flag.Bool(shouldPrintExamplesArg, false, "Print application usage examples")
)

func main() {
	flag.Parse()

	if len(os.Args) == 1 || *shouldPrintHelp {
		fmt.Println(applicationName, version)
		fmt.Println()
		fmt.Println("[ABOUT]")
		fmt.Println("Utility for generating TLS mutual authentication (mTLS) certificate and private key pairs.")
		fmt.Println()
		fmt.Println("[USAGE]")
		flag.PrintDefaults()
		os.Exit(0)
	}

	if *shouldPrintVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	if *shouldPrintExamples {
		fmt.Println(examples)
		os.Exit(0)
	}

	if len(strings.TrimSpace(*certificatePath)) == 0 {
		log.Fatal("Please provide the full certificate file path")
	}

	if len(strings.TrimSpace(*privateKeyPath)) == 0 {
		log.Fatal("Please provide the full private key file path")
	}

	if len(strings.TrimSpace(*organizationNamesCsv)) == 0 {
		log.Fatal("Please provide at least one organization name")
	}

	ips := []net.IP{}
	if len(strings.TrimSpace(*ipAddressesCsv)) > 0 {
		for _, ip := range strings.Split(*ipAddressesCsv, ",") {
			result := net.ParseIP(ip)
			if result == nil {
				log.Fatal("Failed to parse IP address '", ip, "'")
			}
			ips = append(ips, result)
		}
	}

	domainNames := []string{}
	if len(strings.TrimSpace(*domainNamesCsv)) > 0 {
		domainNames = strings.Split(*domainNamesCsv, ",")
	}

	organizationNames := strings.Split(*organizationNamesCsv, "|")
	expirationDate := time.Now().Add(*validHours)

	log.Println("Creating TLS mutual authentication pair...")

	err := mtls.CreateFiles(organizationNames, ips, domainNames, expirationDate, *privateKeyPath, *certificatePath)
	if err != nil {
		log.Fatal(err.Error())
	}

	log.Println("Successfully generated", *certificatePath, "and", *privateKeyPath)
}
