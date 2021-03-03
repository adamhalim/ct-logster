package main

import (
	"github.com/CaliDog/certstream-go"
	"fmt"
	"log"
	"strings"
)
type Message struct {
    cert_index int64
}

type CertInfo struct {
	CertIndex		int32
	SerialNumber	string
	Domain			[]string
	OCSP			string
	CRL				[]string
}

func main() {
	// The false flag specifies that we want heartbeat messages.
	stream, errStream := certstream.CertStreamEventStream(false);
	for {
		select {
		case jq := <-stream:
			_, err := jq.String("message_type");

			if err != nil {	log.Printf("Error decoding jq string"); }
			
			// Here, we grab all fields from the JQ response
			CertInfo, err := jq.Int("data", "cert_index");
			if err != nil {	log.Printf("Error decoding jq cert index."); }

			SerialNumber, err := jq.String("data", "leaf_cert","serial_number")
			if err != nil {	log.Printf("Error decoding jq serial number."); }

			Domain, err := jq.ArrayOfStrings("data", "leaf_cert", "all_domains");
			if err != nil {	log.Printf("Error decoding jq domains."); }

			OCSP, err := jq.String("data", "leaf_cert", "extensions", "authorityInfoAccess");

			// Sometimes, the OCSP - URI and CA Issuers - URI were reversed.
			// This fixes it.
			OCSP = strings.Split(OCSP, "OCSP - URI:")[1];
			if (strings.Contains(OCSP, "CA Issuers - URI:")) {
				OCSP = (strings.Split(OCSP, "\n")[0]) + "\n";
			}

			fmt.Printf("Cert index: %d\n", CertInfo);
			fmt.Printf("Serial number: %s\n", SerialNumber);
			fmt.Printf("Domain: %s\n", Domain);
			fmt.Printf("OCSP URL: %s\n", OCSP);

		case err := <-errStream:
			log.Printf(err.Error());
		}
	}
}