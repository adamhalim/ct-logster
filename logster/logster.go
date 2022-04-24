package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/robfig/cron"

	"github.com/google/certificate-transparency-go/client"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type CTLog struct {
	logClient    client.LogClient
	startIndex   uint64
	currentIndex uint64
	logLock      *sync.Mutex
	inUse        bool
}

type ChainCertIndex struct {
	PEM   string `bson:"pem"`
	Index string
}

type CertInfo struct {
	CertIndex    int            `bson:"certIndex"`
	SerialNumber string         `bson:"serialNumber"`
	Domain       []string       `bson:"domains"`
	OCSP         string         `bson:"OCSP,omitempty"`
	CRL          string         `bson:"CRL,omitempty"`
	CTlog        string         `bson:"ctLog"`
	Certificate  string         `bson:"cert,omitempty"`
	Chain        []string       `bson:"certChain,omitempty"`
	Changes      []StatusUpdate `bson:"Change"`
}

type StatusUpdate struct {
	Status  string
	Time    time.Time
	IsError bool
}

type ChainCertPem struct {
	PEM string `bson:"pem"`
}

var logs []string
var CTLogs []CTLog

func init() {

	// Only init all LogClients if we are
	// running logster.
	if len(os.Args) > 1 {
		if os.Args[1] == "log" {
			logs = loadLogsFromFile()
			initLogClients()
		}
	}

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
		os.Exit(0)
	}
	dbUsername = os.Getenv("USERNAME")
	dbPassword = os.Getenv("PASSWORD")
	dbIp = os.Getenv("IP_ADDRESS")
	dbPort = os.Getenv("PORT")
	dbName = os.Getenv("DB")
	dbChainCollection = os.Getenv("CERT_COLLECTION")
}

// Initialize all CT Log clients
func initLogClients() {
	for _, logUrl := range logs {
		urlPadding := "https://" + logUrl
		logClient := GetLogClient(urlPadding)
		sth, err := logClient.GetSTH(context.Background())
		if err != nil {
			fmt.Printf("Error getting STH for LogClient: %v", err.Error())
			return
		}
		// Give all logs their logClient, start- and end index
		CTLogs = append(CTLogs, CTLog{
			logClient:    logClient,
			startIndex:   sth.TreeSize,
			currentIndex: sth.TreeSize,
			logLock:      &sync.Mutex{},
			inUse:        false,
		})
	}
}

func main() {
	programName := "no args"
	if len(os.Args) > 1 {
		programName = os.Args[1]
		fmt.Println(programName)
	}

	if programName == "log" {
		logMain()

	} else if programName == "rev" {
		//cronjobs start
		log.Println("Create new cron")
		c := cron.New()
		c.AddFunc("@every 1h00m", revocMain)

		// Start cron with one scheduled job
		log.Println("Start cron")
		c.Start()
		log.Printf("Cron Info: %+v\n", c.Entries)
		revocMain()
		time.Sleep(185 * time.Minute)
	} else {
		fmt.Println("Start with either log or rev")
	}
}

func revocMain() {
	fmt.Println("We running revocMain!")
	actualTime := time.Now()
	hour := actualTime.Hour()
	fmt.Println(hour)
	IterateBlock(hour)
}

// Returns the current Tree Size for a give CT log
func getCurrentTreeSize(ctlog CTLog) (uint64, error) {
	sth, err := ctlog.logClient.GetSTH(context.Background())
	if err != nil {
		return 0, err
	}
	return sth.TreeSize, nil
}

func updateTreeSize(ctlog CTLog) (uint64, error) {
	currSTH, err := getCurrentTreeSize(ctlog)
	if err != nil {
		return 0, err
	}
	return currSTH, nil
}

func logMain() {

	// Used for dev-prints
	DEBUG := true

	// Establish connection to MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	uri := "mongodb://" + dbIp + ":" + dbPort
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(uri))

	//disconnects the db when exiting main.
	defer func() {
		if err = client.Disconnect(ctx); err != nil {
			panic(err)
		}
	}()

	err = client.Ping(context.Background(), nil)

	fmt.Println("Connected to MongoDB Server: " + dbIp + ".")

	logTicker := time.NewTicker(500 * time.Millisecond)

	fmt.Println("logTimer fired")
	index := 0
	// Each time our timer is ran, we increment our index and
	// run through each CTLog in CTLogs.

	var counter uint64
	elapsedTime := 0.0
	start := time.Now()
	for _ = range logTicker.C {
		if index >= len(CTLogs) {
			index = 0
		}
		fmt.Printf("Started on index %d\n", index)

		// Here, we update the CTLog's current tree size and proceed to
		// download and process all entires from the CTLog's last tree size
		// to the current one, meaning we download all newly issued certificates
		// for that CT log since the last time the routine was called
		go func(ind int) {

			// Here, we use a lock and check if
			// the CTLog already is in use. This guarantees
			// that code running after this check is only ran
			// on at most one thread. We don't want to be running
			// the same routine on the same CTLog if the previous one
			// hasn't finished running
			CTLogs[ind].logLock.Lock()
			defer setLogNotInUse(&CTLogs[ind])
			defer CTLogs[ind].logLock.Unlock()
			if CTLogs[ind].inUse {
				fmt.Printf("Log already in use.\n")
				return
			}

			CTLogs[ind].inUse = true
			currSTH, err := updateTreeSize(CTLogs[ind])
			if err != nil {
				fmt.Printf("Error getting current tree size: %v", err.Error())
				return
			}

			if currSTH == CTLogs[ind].currentIndex {
				fmt.Printf("Tree size unchanged, nothing to do.\n")
				return
			}

			// Index start at 0, so we need to decrement the current tree size to get the last index.
			// For example, for a tree size of 100, last entry has index 99.
			cert, chain, err := DownloadManyCertsFromCT(CTLogs[ind].currentIndex, currSTH-1, CTLogs[ind].logClient.BaseURI())

			// Sometimes, the tree size updates before the
			// get-entries endpoint does, meaning we try to
			// download entries that are not yet updated.
			if len(cert) == 0 {
				fmt.Printf("No certs downloaded, retrying later...\n")
				return
			}

			// If, for whatever reason, the amount of certificates downloaded
			// isn't the same as the updated tree size - current index, we
			// failed to download all certificates and should try again later.
			// This makes the above len(cert) == 0 check redundant, but
			// I'll leave it here for debugging/logging
			if uint64(len(cert)) != (currSTH - CTLogs[ind].currentIndex) {
				fmt.Printf("Wrong amount of certs downloaded, retrying later...\n")
				return
			}

			// Here, we go through each chain certificate and filter out all
			// duplicates. []uniqueCerts now only contains unique chain certs
			// This massively increases performance, as we need to do less checks
			// later on to see if a cert already is in the DB.
			var uniqueCerts []string
			m := map[string]bool{}
			for _, v := range chain {
				for _, c := range v {
					if !m[c] {
						m[c] = true
						uniqueCerts = append(uniqueCerts, c)
					}
				}
			}

			// Map all chain certificates with their
			// index in the DB
			var certIDS []ChainCertIndex
			for _, entry := range uniqueCerts {
				chainID, err := InsertChainCertIntoDB(*client, cancel, ChainCertPem{
					PEM: entry,
				})
				certIDS = append(certIDS, ChainCertIndex{
					PEM:   entry,
					Index: chainID,
				})
				if err != nil {
					fmt.Printf("Error inserting chain cert into DB: %v", err.Error())
					return
				}
			}
			// For each newly issued certificate, we parse them to *X509.Certificates
			// and extract the data we want for our CertInfo struct.
			for i := 0; i < len(cert); i++ {
				// We decode the PEM to a *x509.Certificate,to access
				// the certificate's fields easily.
				x509ParsedCert, err := DecodePemsToX509(cert[i].PEM)
				if err != nil {
					fmt.Printf("Error parsing certs to x509: %v", err.Error())
					// If this fails, there probably is an error in the certificate
					// which stops it from being parsed correctly. When this happens,
					// we skip the entire batch of new certificates to avoid attempting
					// to parse it again. This happens extremely rarely and shouldn't
					// have any noticable impact on the amount of certificates missed.
					skipBatchPrint(CTLogs[ind], currSTH)
					CTLogs[ind].currentIndex = currSTH
					return
				}

				// Initialize structi with all fields
				certificate := CertInfo{
					CertIndex:    int(cert[i].Index),
					SerialNumber: x509ParsedCert[0].SerialNumber.String(),
					Domain:       x509ParsedCert[0].DNSNames,
					Certificate:  cert[i].PEM,
					Chain:        chain[i],
					CTlog:        CTLogs[ind].logClient.BaseURI(),
				}

				// Check for CRL URL
				if len(x509ParsedCert[0].CRLDistributionPoints) > 0 {
					certificate.CRL = x509ParsedCert[0].CRLDistributionPoints[0]
				}

				// Check for OCSP URL
				if len(x509ParsedCert[0].OCSPServer) > 0 {
					certificate.OCSP = x509ParsedCert[0].OCSPServer[0]
				}

				// For each chain cert in the entry, we take the
				// corresponding MongoDB ID that we acquired earlier
				var uniqueIDs []string
				for _, uniqueCert := range certIDS {
					for _, chainCert := range chain[i] {
						if uniqueCert.PEM == chainCert {
							uniqueIDs = append(uniqueIDs, uniqueCert.Index)
						}
					}
				}

				certificate.Chain = uniqueIDs
				certificate.Certificate = cert[i].PEM
				err = InsertCertIntoDB(*client, cancel, certificate)
				if err != nil {
					fmt.Printf("Error inserting cert into DB: %v", err.Error())
					return
				}
			}
			counter += currSTH - CTLogs[ind].currentIndex
			// We only increment our currentIndex if everything is
			// succesful. If anything fails, we don't update it.
			// This will result in duplicate entries if we exit
			// out midway through inserting the certificates.

			// TODO: Might be worth to implement some kind of logic
			// to prevent this. Since insertion is done
			// synchronously, we could return the index for
			// each successful entry perhaps and update each entry?
			// Another option is doing insertion in batches.
			// We either insert all, or nothing.
			CTLogs[ind].currentIndex = currSTH
		}(index)
		index++
		elapsedTime += 0.5
		if DEBUG {
			fmt.Printf("New certs: %d.\n", counter)
			fmt.Printf("Certs per second: %.2f\n", float32(counter)/float32(time.Since(start).Seconds()))
		}
	}
}

func setLogNotInUse(ctlog *CTLog) {
	ctlog.inUse = false
}

// Prints which log the error was caused by, what the log's current
// index is and what the log's current tree size, as well as how many
// log entries were skipped.
// TODO: Maybe use log instead of fmt? Not sure how to get
// the output to file though if redirecting output to file.
// (log doesn't seem to go to stdout?)
func skipBatchPrint(ctlog CTLog, currSTH uint64) {
	fmt.Printf("******************************\n")
	fmt.Printf("Error caused Logster to skip entire batch.\n")
	fmt.Printf("CTLog URL: %s.\n", ctlog.logClient.BaseURI())
	fmt.Printf("Current index: %d. Current tree size: %d.\n", ctlog.currentIndex, currSTH)
	fmt.Printf("Log entries skipped: %d.\n", currSTH-ctlog.currentIndex+1)
	fmt.Printf("******************************\n")
}

// Reads all ctlog URLs from file
func loadLogsFromFile() []string {
	fileName := "ctlogs.txt"
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)

	var logArray []string
	for scanner.Scan() {
		logArray = append(logArray, scanner.Text())
	}
	// If the file was empty, quit.
	if len(logArray) < 1 {
		log.Fatal(fmt.Sprintf("No CTLogs found in %s.\n", fileName))
	}
	return logArray
}
