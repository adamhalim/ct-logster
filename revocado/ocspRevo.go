package revocado

import (
	"fmt"
	"bytes"
	"encoding/base64"
	"crypto/x509"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"net/http"
	"errors"
	"math/big"
	"encoding/asn1"
	"crypto/x509/pkix"
	"crypto"
	"math/rand"
	"strconv"
	"time"
	"strings"
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
		reason := "Revoked:" + strconv.Itoa(ocspResp.RevocationReason)
		return reason, nil
	} else {
		return "Unexcpected", nil
	}
}

// sendOCSPRequest attempts to request an OCSP response from the
// server. The error only indicates a failure to *fetch* the
// certificate, and *does not* mean the certificate is valid.
func sendOCSPRequest(url string, req []byte, issuer *x509.Certificate) (ocspResponse *ocsp.Response, err error) {
    var resp *http.Response

	client := http.Client{
		Timeout: 10 * time.Second,
	}

    if len(req) > 256 {
        buf := bytes.NewBuffer(req)
        resp, err = client.Post(url, "application/ocsp-request", buf)
    } else {
        reqURL := url + "/" + base64.StdEncoding.EncodeToString(req)
        resp, err = client.Get(reqURL)
    }

	if err != nil {
		if strings.Contains(err.Error(),"(Client.Timeout exceeded while awaiting headers)"){
			fmt.Println("Timeout")
			return nil, errors.New("request canceled while waiting for connection")
		}
		return nil, err
    }

    if resp.StatusCode != http.StatusOK {
		respStat := "Status ="
		respStat = respStat + strconv.Itoa(resp.StatusCode)
        return nil, errors.New(respStat)
    }

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, errors.New("Could not read body")
    }

	resp.Body.Close()
    return ocsp.ParseResponse(body, issuer)
}

func randomSerialTest(url string, issuer *x509.Certificate)  (ocspResponse *ocsp.Response, err error){
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &publicKeyInfo)
	if err != nil{
		fmt.Println("Error unmarshaling ASN1 info")
	}

	var ocsp_req ocsp.Request
	ocsp_req.HashAlgorithm = crypto.Hash(crypto.SHA1)
	h := ocsp_req.HashAlgorithm.New()
	h.Write(publicKeyInfo.PublicKey.RightAlign())
	ocsp_req.IssuerKeyHash = h.Sum(nil)

	h.Reset()
	h.Write(issuer.RawSubject)
	ocsp_req.IssuerNameHash = h.Sum(nil)

	random_serial := [20]byte{}
	copy(random_serial[:], "crt.sh")
	_, err = rand.Read(random_serial[6:])
	if err != nil{
		fmt.Println("Error reading random serial")
	}

	ocsp_req.SerialNumber = big.NewInt(0)
	ocsp_req.SerialNumber.SetBytes(random_serial[:])

	ocsp_req_bytes, err := ocsp_req.Marshal()
	if err != nil{
		fmt.Println("Rip request bytes")
	}

	return sendOCSPRequest(url, ocsp_req_bytes, issuer)
}
