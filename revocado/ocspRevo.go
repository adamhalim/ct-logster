package revocado

import (
	"bytes"
	"encoding/base64"
	"crypto/x509"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"net/http"
	"errors"
)


func GetOCSP(url string, issuer *x509.Certificate, cert *x509.Certificate) (status string, err error){
	req, err := ocsp.CreateRequest(cert, issuer, nil)
	ocspResp, err := sendOCSPRequest(url, req,issuer)
	if err != nil{
		return "", err
	}

	if ocspResp.Status == ocsp.Good {
		return "Good", nil
	} else if ocspResp.Status == ocsp.Unknown {
		return "Unknown", nil
	} else if ocspResp.Status == ocsp.Revoked {
		return "Revoked", nil
	} else {
		return "Unexcpected", nil
	}
}

// sendOCSPRequest attempts to request an OCSP response from the
// server. The error only indicates a failure to *fetch* the
// certificate, and *does not* mean the certificate is valid.
func sendOCSPRequest(url string, req []byte, issuer *x509.Certificate) (ocspResponse *ocsp.Response, err error) {
    var resp *http.Response

    if len(req) > 256 {
        buf := bytes.NewBuffer(req)
        resp, err = http.Post(url, "application/ocsp-request", buf)
    } else {
        reqURL := url + "/" + base64.StdEncoding.EncodeToString(req)
        resp, err = http.Get(reqURL)
    }

    if err != nil {
        return nil, errors.New("Error making get/post request")
    }

    if resp.StatusCode != http.StatusOK {
        return nil, errors.New("Status for request not OK")
    }

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, errors.New("Could not read body")
    }
    resp.Body.Close()

    return ocsp.ParseResponse(body, issuer)
}
