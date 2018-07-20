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
	"crypto/x509"
	"crypto/x509/pkix"
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
	organisationName   = flag.String("name", "Acme Inc", "Legal name of the organisation")
	organisationNumber = flag.String("number", "0", "Registered company number, SIRET, DUNS, or other number identifying the organisation")
	countryCode        = flag.String("country", "US", "Two letter ISO country code where the organisation is registered")

	// Technical settings with opinionated defaults
	// ...private key length; 4048 is a widely accepted maximum.
	rsaBits = flag.Int("rsa-bits", 4048, "Size of RSA key to generate")
	// ...increment the serial number each time a new organisational root certificate is made
	serialNumber = flag.Int("serial", 1, "Serial number of certificate")
	// ...validity of the root determines the maximum validity of all other certificates
	validFor = flag.Duration("duration", 20*365*24*time.Hour, "Duration that certificate is valid for")
)

// Make an organisation root certificate:
//
//     ./oamake-root --name "My Company Inc" --country FR --number 123123123
//
func main() {
	flag.Parse()

	if len(*organisationName) == 0 {
		log.Fatalf("Missing required --name parameter")
	} else if len(*organisationNumber) == 0 {
		log.Fatalf("Missing required --number parameter")
	} else if len(*countryCode) == 0 {
		log.Fatalf("Missing required --country parameter")
	}

	// Create a private key
	priv, err := rsa.GenerateKey(rand.Reader, *rsaBits)
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
	}

	// Prepare a template certificate
	notBefore := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(int64(*serialNumber)),
		Subject: pkix.Name{
			Organization: []string{*organisationName},
			Country:      []string{*countryCode},
			SerialNumber: *organisationNumber,
			CommonName:   fmt.Sprintf("%s Root CA", *organisationName),
		},
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(*validFor),

		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:     true,

		BasicConstraintsValid: true,
	}

	// Create the root certificate, signed by itself
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	// Write the certificate
	certOut, err := os.Create("root-cert.pem")
	if err != nil {
		log.Fatalf("failed to open root-cert.pem for writing: %s", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	log.Print("written root-cert.pem\n")

	// Write the secret private key
	keyOut, err := os.OpenFile("root-key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Print("failed to open root-key.pem for writing:", err)
		return
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	log.Print("written root-key.pem\n")
}
