package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os/exec"
	"strings"
)

// This function will contact a CT log and retrieve
// the certificate and its certificate chain
func GetCertChain(index string, url string) (cert string, chain string) {
	// Executes the ctclient from https://github.com/google/certificate-transparency-go
	// Assumes ctclient.go is compiled and binary (./ctclient) is in same directory as this file
	cmd, err := exec.Command("./ctclient", fmt.Sprintf("-first=%v", index), fmt.Sprintf("-last=%v", index), "-chain=true", "-text=false", fmt.Sprintf("-log_uri=https://%v", url), "getentries").Output()
	if err != nil {
		fmt.Errorf("Error yo")
	}

	// Convert output string and parse it
	// TODO: Parse this better, probably very error prone.
	certString := string(cmd[:])

	certArr := strings.SplitAfterN(certString, "\n", 2)[1:]
	certArr = strings.SplitAfter(certArr[0], "-----END CERTIFICATE-----")

	var certificate, certChain string
	for i := 0; i < len(certArr); i++ {
		if i == 0 {
			certificate = certArr[i]
		} else {
			certChain += certArr[i]

		}
	}
	return certificate, certChain
}

// Pretty much stole this and getTlsCert()
// from https://gist.github.com/laher/5795578.
// Takes a PEM string and will decode 
// and return all X509 certs
func DecodePem(certInput string) (certs[] *x509.Certificate, err error) {
	chainz := getTlsCert(certInput)
	parsedCerts := []*x509.Certificate{}

	for _, cert := range chainz.Certificate {
		x509Cert, err := x509.ParseCertificate(cert)
		if err != nil {
			return nil, err
		}
		parsedCerts = append(parsedCerts, x509Cert)
	}
	return parsedCerts, nil
}

func getTlsCert(certInput string) (tls.Certificate) {
	var cert tls.Certificate
	certPEMBlock := []byte(certInput)
	var certDERBlock *pem.Block
	for {
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		}
	}
	return cert
}
