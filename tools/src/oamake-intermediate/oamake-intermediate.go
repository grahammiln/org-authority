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
	organisationUnit = flag.String("name", "Litigation Division", "Name of organisation department, division, or group")

	// Parent certificate
	parentCertPath = flag.String("cert", "root-cert.pem", "Path to parent certificate")
	parentKeyPath  = flag.String("key", "root-key.pem", "Path to parent key")

	// Technical settings with opinionated defaults
	// ...private key length; 4048 is a widely accepted maximum.
	rsaBits = flag.Int("rsa-bits", 4048, "Size of RSA key to generate")
	// ...validity of the the certificate; must be less than parent certificate's validity
	validFor = flag.Duration("duration", 5*365*24*time.Hour, "Duration that certificate is valid for")
)

// Make an organisation intermediate certificate:
//
//     ./oamake-intermediate --cert root-cert.pem --key root-key.pem --name "Litigation Division"
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
		log.Fatalf("intermediate can not remain valid after parent, maximum duration: %s", time.Until(parentCert.NotAfter).String)
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

		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:     true,

		BasicConstraintsValid: true,
	}
	template.Subject.OrganizationalUnit = []string{*organisationUnit}
	template.Subject.CommonName = fmt.Sprintf("%s Intermediate CA", *organisationUnit)

	// Create the intermediate certificate, signed by the parent
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parentCert, &priv.PublicKey, parent.PrivateKey)
	if err != nil {
		log.Fatalf("failed to create certificate: %s", err)
	}

	// Write the certificate
	certOut, err := os.Create("intermediate-cert.pem")
	if err != nil {
		log.Fatalf("failed to open intermediate-cert.pem for writing: %s", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	log.Print("written intermediate-cert.pem\n")

	// Write the secret private key
	keyOut, err := os.OpenFile("intermediate-key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Print("failed to open intermediate-key.pem for writing:", err)
		return
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	log.Print("written intermediate-key.pem\n")
}
