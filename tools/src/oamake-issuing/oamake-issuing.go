// Copyright 2018 Graham Miln <https://miln.eu> All rights reserved.
//
// Based on The Go Authors' `generate_cert.go` source code.
// Copyright 2009 The Go Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

var (
	// Organisation
	organisationUnit = flag.String("name", "Invoicing", "Name of organisation department, division, or group")

	// Parent certificate
	parentCertPath = flag.String("cert", "intermediate-cert.pem", "Path to parent certificate")
	parentKeyPath  = flag.String("key", "intermediate-key.pem", "Path to parent key")

	// Technical settings with opinionated defaults
	// ...private key length; 4048 is a widely accepted maximum.
	rsaBits = flag.Int("rsa-bits", 2048, "Size of RSA key to generate")
	// ...validity of the the certificate; must be less than parent certificate's validity
	validFor = flag.Duration("duration", 2*365*24*time.Hour, "Duration that certificate is valid for")

	// Revocation and control
	ocspURL = flag.String("ocsp", "", "URL to OCSP server; RFC 5280, 4.2.2.1 (optional)")
	certURL = flag.String("url", "", "URL to issuing certificate in ASN.1 DER format; RFC 5280, 4.2.2.1 (optional)")
	crlURL  = flag.String("crl", "", "URL to Certificate Revocation List (CRL) (optional)")
)

// Make an organisation intermediate certificate:
//
//     ./oamake-issuing --cert intermediate-cert.pem --key intermediate-key.pem --name "Invoicing"
//
func main() {
	flag.Parse()

	if len(*organisationUnit) == 0 {
		log.Fatalf("Missing required --name parameter")
	} else if len(*parentCertPath) == 0 {
		log.Fatalf("Missing required --cert parameter")
	} else if len(*parentKeyPath) == 0 {
		log.Fatalf("Missing required --key parameter")
	}

	// Read parent certificate and key
	parent, err := tls.LoadX509KeyPair(*parentCertPath, *parentKeyPath)
	if err != nil {
		log.Fatalf("failed to load parent: %s", err)
	}
	// ...decode parent certificate
	parentCert, err := x509.ParseCertificate(parent.Certificate[0])
	if err != nil {
		log.Fatalf("failed to decode parent cert: %s", err)
	}

	// Create a private key
	priv, err := rsa.GenerateKey(rand.Reader, *rsaBits)
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
	}

	// Prepare a template certificate
	notBefore := time.Now()
	notAfter := notBefore.Add(*validFor)
	if notAfter.After(parentCert.NotAfter) {
		log.Fatalf("issuing can not remain valid after parent, maximum duration: %s", time.Until(parentCert.NotAfter).String)
	}

	// ...random serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      parentCert.Subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCRLSign,
		IsCA:     true,

		// Limit distance to issuer's child certificates
		MaxPathLen:     0,
		MaxPathLenZero: true,

		BasicConstraintsValid: true,
	}
	template.Subject.OrganizationalUnit = []string{*organisationUnit}
	template.Subject.CommonName = fmt.Sprintf("%s Issuing CA", *organisationUnit)

	if len(*ocspURL) > 0 {
		template.OCSPServer = []string{*ocspURL}
	}
	if len(*certURL) > 0 {
		template.IssuingCertificateURL = []string{*certURL}
	}
	if len(*crlURL) > 0 {
		template.CRLDistributionPoints = []string{*crlURL}
	}

	// Create the intermediate certificate, signed by the parent
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parentCert, &priv.PublicKey, parent.PrivateKey)
	if err != nil {
		log.Fatalf("failed to create certificate: %s", err)
	}

	// Write the certificate
	certOut, err := os.Create("issuing-cert.pem")
	if err != nil {
		log.Fatalf("failed to open issuing-cert.pem for writing: %s", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	log.Print("written issuing-cert.pem\n")

	// Write the secret private key
	keyOut, err := os.OpenFile("issuing-key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Print("failed to open issuing-key.pem for writing:", err)
		return
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	log.Print("written issuing-key.pem\n")
}
