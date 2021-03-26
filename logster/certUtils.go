package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
)

var once sync.Once
var lock = &sync.Mutex{}
var ctx context.Context

var (
	httpClient http.Client
	logClients map[string]client.LogClient = make(map[string]client.LogClient)
)

func init() {
	ctx = context.Background()
}

// Returns the httpClient. Only 1 client is created in total.
func GetHttpClient() *http.Client {
	once.Do(func() {
		httpClient = http.Client{
			Timeout: time.Duration(5 * time.Second),
		}
	})
	return &httpClient
}

// If there is no LogClient for the given CT log,
// one will be created and returned. Otherwise the
// LogClient is returned. Mutex lock prevents multiple
// copies of same LogClient being created.
func GetLogClient(url string) client.LogClient {
	lock.Lock()
	defer lock.Unlock()
	logClient, ok := logClients[url]

	// If !ok, the CT log doesn't have a LogClient
	if !ok {
		logClient = client.LogClient{}
		opts := jsonclient.Options{}
		jsclient, _ := jsonclient.New(url, GetHttpClient(), opts)
		logClient.JSONClient = *jsclient
		logClients[url] = logClient
		return logClient
	}
	return logClient
}

// This function will contact a CT log and retrieve
// the certificate and its certificate chain
func GetCertChain(index string, url string) (cert string, chain string, err error) {
	// Executes the ctclient from https://github.com/google/certificate-transparency-go
	// Assumes ctclient.go is compiled and binary (./ctclient) is in same directory as this file
	cmd, err := exec.Command("./ctclient", fmt.Sprintf("-first=%v", index), fmt.Sprintf("-last=%v", index), "-chain=true", "-text=false", fmt.Sprintf("-log_uri=https://%v", url), "getentries").Output()
	if err != nil {
		return "", "", err
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
	return certificate, certChain, nil
}

// Pretty much stole this and getTlsCert()
// from https://gist.github.com/laher/5795578.
// Takes a PEM string and will decode
// and return all X509 certs
func DecodePem(certInput string) (certs []x509.Certificate, err error) {
	chainz := getTlsCert(certInput)
	parsedCerts := []x509.Certificate{}

	for _, cert := range chainz.Certificate {
		x509Cert, err := x509.ParseCertificate(cert)
		if err != nil {
			return nil, err
		}
		parsedCerts = append(parsedCerts, *x509Cert)
	}
	return parsedCerts, nil
}

func getTlsCert(certInput string) tls.Certificate {
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

// Given the CT log and index, this function will
// download the associated certificate(s) and return them
// as PEM strings
func DownloadCertFromCT(index int, url string) (cert string, chain []string, err error) {
	urlPadding := "https://" + url

	logClient := GetLogClient(urlPadding)
	i64 := int64(index)
	entry, err := logClient.GetRawEntries(context.Background(), i64, i64)
	if err != nil {
		return "", nil, err
	}

	// Iterate through all entires (we only really get one at a time,
	// so this loop will only be ran once)
	for _, entry := range entry.Entries {
		logentry, _ := ct.RawLogEntryFromLeaf(i64, &entry)
		if logentry != nil {
			var cert string
			var PEMchain []string
			ts := logentry.Leaf.TimestampedEntry
			switch ts.EntryType {
			case ct.X509LogEntryType:
				cert += getPEMdata(ts.X509Entry.Data)
			case ct.PrecertLogEntryType:
				cert += getPEMdata(logentry.Cert.Data)
			default:
				fmt.Printf("Unhandled log entry type %d\n", ts.EntryType)
			}
			for _, c := range logentry.Chain {
				PEMchain = append(PEMchain, getPEMdata(c.Data))
			}
			return cert, PEMchain, nil
		}
	}
	return "", nil, errors.New("No CT log entires found.")
}

// Will take raw data and decode it to a
// PEM string.
func getPEMdata(data []byte) string {
	// pem.Encode will write to this buffer that we then convert to a string
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: data}); err != nil {
		fmt.Printf("Failed to PEM encode cert: %q", err.Error())
	}
	s := buf.String()
	return s
}
