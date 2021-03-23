package main
import (
	"os/exec"
	"fmt"	
	"strings"
)

// This function will contact a CT log and retrieve
// the certificate and its certificate chain
func GetCertChain(index string, url string) (cert string, chain string) {
	// Executes the ctclient from https://github.com/google/certificate-transparency-go
	// Assumes ctclient.go is compiled and binary (./ctclient) is in same directory as this file
	cmd, err  := exec.Command("./ctclient", fmt.Sprintf("-first=%v", index), fmt.Sprintf("-last=%v", index), "-chain=true", "-text=false", fmt.Sprintf("-log_uri=https://%v", url),  "getentries").Output()
	if err != nil {
		fmt.Errorf("Error yo")
	}

	// Convert output string and parse it
	// TODO: Parse this better, probably very error prone.
	certString := string(cmd[:])

	certArr := strings.SplitAfterN(certString, "\n", 2)[1:]
	certArr = strings.SplitAfter(certArr[0], "-----END CERTIFICATE-----" )

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