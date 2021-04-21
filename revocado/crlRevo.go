package revocado

import(
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

// Downloads a file and saves it in memory. Returns the HTTP response
func downloadCRL(url string) (response *http.Response, err error) {

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	// Check server response
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Bad status: %s", resp.Status)
	}

	if err != nil {
		return nil, err
	}

	// Return the response
	return resp, nil
}

// Checks to see if a certificate is in the .crl
func IsCertInCRL(crlURL string, serialnumber string) (bool, error)  {
	crl, err := downloadCRL(crlURL)
	if err != nil {
		fmt.Printf("%s", err)
		return false, err
	}

	// Convert response body to []byte array
	crlArray, err := ioutil.ReadAll(crl.Body)
	if err != nil {
		fmt.Printf("%s", err)
		return false, err
	}

	// We parse the CRL file.
	certList, err := x509.ParseCRL(crlArray)
	if err != nil {
		fmt.Printf("%s", err)
		return false, err
	}

	validCert := false

	// Iterate through all revoked certificates
	for i := 0; i < len(certList.TBSCertList.RevokedCertificates); i++ {
		// Convert to hex-string
		h := fmt.Sprintf("%x", certList.TBSCertList.RevokedCertificates[i].SerialNumber)
		if strings.EqualFold(strings.ToUpper(serialnumber), strings.ToUpper(h)) {
			validCert = true
			break
		}
	}
	return validCert, nil
}
