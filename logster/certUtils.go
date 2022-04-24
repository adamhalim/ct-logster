package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
)

type CertWithIndex struct {
	PEM   string
	Index int64
}

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
// ----- This function is no longer used! -----
func GetChainCert(index string, url string) (cert string, chain string, err error) {
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
func DecodePemsToX509(certInput string) (certs []x509.Certificate, err error) {
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
func DownloadCertsFromCT(index int, url string) (cert string, chain []string, err error) {
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

// Given the CT log and index, this function will
// download the associated certificate(s) and return them
// as CertWithIndex structs. CertWithIndex contains the PEM
// cert as string as well as it's CT log index
func DownloadManyCertsFromCT(startIndex uint64, endIndex uint64, url string) (cert []CertWithIndex, chain [][]string, err error) {

	logClient := GetLogClient(url)
	starti64 := int64(startIndex)
	endi64 := int64(endIndex)
	var certs []CertWithIndex
	var PEMchain [][]string

	// When querying the CT logs, we don't necessarily get all entires
	// from one request. Therefore, after each request, we need  to
	// increment our starting index with as many results as we got
	// from the previous query. We do this until we get all entires.
	for starti64 <= endi64 {
		entries, err := logClient.GetRawEntries(context.Background(), starti64, endi64)
		if err != nil {
			return nil, nil, err
		}

		currIndex := starti64
		// Iterate through all entires CT log entires (and
		// decode each entry to get it's cert + the chain.
		for _, entries := range entries.Entries {
			logentry, _ := ct.RawLogEntryFromLeaf(currIndex, &entries)
			if logentry != nil {
				ts := logentry.Leaf.TimestampedEntry
				switch ts.EntryType {
				case ct.X509LogEntryType:
					certs = append(certs, CertWithIndex{
						PEM:   getPEMdata(ts.X509Entry.Data),
						Index: logentry.Index,
					})
				case ct.PrecertLogEntryType:
					certs = append(certs, CertWithIndex{
						PEM:   getPEMdata(logentry.Cert.Data),
						Index: logentry.Index,
					})
				default:
					fmt.Printf("Unhandled log entry type %d\n", ts.EntryType)
				}
				// Append each chain cert to a slice
				var certPemChain []string
				for _, c := range logentry.Chain {
					certPemChain = append(certPemChain, getPEMdata(c.Data))
				}
				PEMchain = append(PEMchain, certPemChain)
			}
			currIndex++
		}
		// Increment our starting index with as many entries we received
		starti64 += int64(len(entries.Entries))
	}
	// When all entires are received, we can return
	if len(certs) > 0 && starti64 >= endi64 {
		return certs, PEMchain, nil
	}
	return nil, nil, errors.New("No CT log entires found.")
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

// Returns the cert rate in certificates per second between
// specified interval.
// The tolerance should be between 0-1 and specifies how close we can
// be to our hoursBack before we are satisfied. A tolerance of 0.1 means we need
// to be ± 10 % within our target.
func (ctlog CTLog) GetCertRateHistory(hoursBack float64, duration float64, tolerance float64) (float64, error) {
	firstIndex, firstHour, err := ctlog.getIndexHistory(hoursBack, tolerance)
	if err != nil {
		return 0, err
	}

	secondIndex, secondHour, err := ctlog.getIndexHistory(hoursBack-duration, tolerance)
	if err != nil {
		return 0, err
	}

	// How many certs / second between the two indexes
	rate := (float64(secondIndex) - float64(firstIndex)) / ((float64(firstHour) - float64(secondHour)) * 3600)
	if math.IsNaN(rate) {
		return 0, nil
	}
	return rate, nil
}

// Finds index of a CTLog that is a specified amount of hours
// back in time relative to the current tree.
func (ctlog CTLog) getIndexHistory(hoursBack float64, tolerance float64) (uint64, float64, error) {
	if tolerance <= 0 || tolerance > 1 {
		return 0, 0, errors.New("Tolerance not within the limit 0-1.")
	}
	treeSize, err := ctlog.logClient.GetSTH(context.Background())
	if err != nil {
		return 0, 0, err
	}

	// We use an initial offset of 0.1 % of the treeSize
	indexOffset := math.Ceil(float64(treeSize.TreeSize)*0.001) + 1
	currIndex := float64(treeSize.TreeSize) - indexOffset

	// We get the latest entry in the CTLog and record the timestamp
	// of that entry.
	entry, err := ctlog.logClient.GetRawEntries(context.Background(), int64(treeSize.TreeSize-1), int64(treeSize.TreeSize-1))
	if err != nil {
		return 0, 0, err
	}
	logentry, err := ct.RawLogEntryFromLeaf(int64(currIndex), &(entry.Entries[0]))
	if err != nil {
		return 0, 0, err
	}
	timeNow := time.Unix(int64(logentry.Leaf.TimestampedEntry.Timestamp), 0)

	// Bounds check; are our hours within the scope of the CTLog?
	_, err = hourOffsetInBounds(ctlog, timeNow, hoursBack)
	if err != nil {
		return 0, 0, err
	}

	var timeDiff int64
	var hourDiff float64
	tries := 100
	// As long as we're not within 10 % of hour time difference, we keep searching
	// for an entry that was logged the specified amount of hours back
	for {
		tries--
		currIndex = float64(treeSize.TreeSize) - indexOffset
		entry, err := ctlog.logClient.GetRawEntries(context.Background(), int64(currIndex), int64(currIndex))
		if err != nil {
			fmt.Printf("Error getting raw entires: %v\n", err.Error())
			break
		}
		logentry, err := ct.RawLogEntryFromLeaf(int64(currIndex), &(entry.Entries[0]))
		entryTime := int64(logentry.Leaf.TimestampedEntry.Timestamp)

		// Unix times
		timeDiff = timeNow.Unix() - entryTime
		if err != nil {
			fmt.Printf("Error getting log entry: %v\n", err.Error())
			break
		}

		// Time is in ms, divide by 3600 * 1000 to get hours
		hourDiff = float64(timeDiff) / (3600000)

		if tries == 0 {
			return 0, 0, errors.New(fmt.Sprintf("Too many attempts getting index %.2f hours back, Aborting.", hoursBack))
		}

		// This logic only works if the log has ~linear growth rate.
		// It will fail for logs with large batches of certs.
		// Also won't work for small logs (which don't matter much anyways)
		// TODO: Use a SMA with binary search or something similar?
		indexOffset = math.Ceil((hoursBack/hourDiff)*indexOffset) + 1

		// Bad check here. While we are out of bounds, there might still be
		// an entry at the start of the log within our target. Will
		// leave this for now...
		// TODO: Improve this, we miss a lot of certificates when we
		// have long hour offsets
		if indexOffset > float64(treeSize.TreeSize) {
			indexOffset *= 0.5
			continue
		}
		// Break when we are within our tolerance
		if float64(hourDiff) > (hoursBack*(1-tolerance)) && float64(hourDiff) < (hoursBack*(1+tolerance)) {
			break
		}
	}
	return uint64(currIndex), hourDiff, nil
}

// Checks if to see the hours are in the scope of the log's life.
// To do this, we grab the first entry in the log and see how many
// hours ago it was uploaded.
func hourOffsetInBounds(ctlog CTLog, timeNow time.Time, hours float64) (bool, error) {
	entry, err := ctlog.logClient.GetRawEntries(context.Background(), 0, 0)
	if err != nil {
		return false, err
	}
	logentry, err := ct.RawLogEntryFromLeaf(0, &(entry.Entries[0]))
	if err != nil {
		return false, err
	}

	entryTime := int64(logentry.Leaf.TimestampedEntry.Timestamp)
	timeDiff := timeNow.Unix() - entryTime
	// Time is in ms, divide by 3600 * 1000 to get hours
	hourDiff := float64(timeDiff) / (3600000)

	if hourDiff < hours {
		return false, errors.New(fmt.Sprintf("Offset of %.2f hours is greater than first entry in log.", hours))
	}
	return true, nil
}
