package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

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

var logs []string
var CTLogs []CTLog

func init() {

	test := []string{"ct.browser.360.cn/2021/",
		"ct.browser.360.cn/2022/",
		"ct.cloudflare.com/logs/nimbus2021/",
		"ct.cloudflare.com/logs/nimbus2022/",
		"ct.cloudflare.com/logs/nimbus2023/",
		"ct.googleapis.com/icarus/",
		"ct.googleapis.com/logs/argon2018/",
		"ct.googleapis.com/logs/argon2019/",
		"ct.googleapis.com/logs/argon2020/",
		"ct.googleapis.com/logs/argon2021/",
		"ct.googleapis.com/logs/argon2022/",
		"ct.googleapis.com/logs/argon2023/",
		"ct.googleapis.com/logs/crucible/",
		"ct.googleapis.com/logs/solera2021/",
		"ct.googleapis.com/logs/solera2022/",
		"ct.googleapis.com/logs/xenon2020/",
		"ct.googleapis.com/logs/xenon2021/",
		"ct.googleapis.com/logs/xenon2022/",
		"ct.googleapis.com/logs/xenon2023/",
		"ct.googleapis.com/pilot/",
		"ct.googleapis.com/rocketeer/",
		"ct.googleapis.com/skydiver/",
		"ct.googleapis.com/submariner/",
		"ct.googleapis.com/testtube/",
		"ct.trustasia.com/log2022/",
		"ct.trustasia.com/log2023/",
		"ct1.digicert-ct.com/log/",
		"ct2021.trustasia.com/log2021/",
		"dodo.ct.comodo.com/",
		"mammoth.ct.comodo.com/",
		"nessie2021.ct.digicert.com/log/",
		"nessie2022.ct.digicert.com/log/",
		"nessie2023.ct.digicert.com/log/",
		"oak.ct.letsencrypt.org/2021/",
		"oak.ct.letsencrypt.org/2022/",
		"oak.ct.letsencrypt.org/2023/",
		"sabre.ct.comodo.com/",
		"testflume.ct.letsencrypt.org/2021/",
		"testflume.ct.letsencrypt.org/2022/",
		"testflume.ct.letsencrypt.org/2023/",
		"yeti2021.ct.digicert.com/log/",
		"yeti2022.ct.digicert.com/log/",
		"yeti2023.ct.digicert.com/log/"}

	logs = test
	//logs = []string{"oak.ct.letsencrypt.org/2021/"}
	initLogClients()

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
	dbCollection = os.Getenv("MAIN_COLLECTION")
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

// 1102495 - 1105460

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

func main() {

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

	// 1203840 - 1280163
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
			if CTLogs[ind].inUse {
				fmt.Printf("Log already in use.\n")
				CTLogs[ind].logLock.Unlock()
				return
			}

			CTLogs[ind].inUse = true
			CTLogs[ind].logLock.Unlock()

			currSTH, err := updateTreeSize(CTLogs[ind])
			if err != nil {
				fmt.Printf("Error getting current tree size: %v", err.Error())
				CTLogs[ind].inUse = false
				return
			}

			if currSTH == CTLogs[ind].currentIndex {
				fmt.Printf("Tree size unchanged, nothing to do.\n")
				CTLogs[ind].inUse = false
				return
			}

			cert, chain, err := DownloadManyCertsFromCT(CTLogs[ind].currentIndex, currSTH, CTLogs[ind].logClient.BaseURI())

			// Sometimes, the tree size updates before the
			// get-entries endpoint does, meaning we try to
			// download entries that are not yet updated.
			if len(cert) == 0 {
				CTLogs[ind].inUse = false
				return
			}

			// If, for whatever reason, the amount of certificates downloaded
			// isn't the same as the updated tree size - current index, we
			// failed to download all certificates and should try again later.
			// This makes the above len(cert) == 0 check redundant, but
			// I'll leave it here for debugging/logging
			if uint64(len(cert)) != (currSTH-CTLogs[ind].currentIndex)+1 {
				fmt.Printf("Wrong amount of certs downloaded, retrying later...\n")
				CTLogs[ind].inUse = false
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
					CTLogs[ind].inUse = false
					return
				}
			}
			// Ensure that we downlaod the exact amount of entries
			// that we specified
			diff := currSTH - CTLogs[ind].currentIndex
			if int(diff) != len(cert)-1 {
				fmt.Printf("Wrong amount of certs downloaded, retrying later...\n")
				CTLogs[ind].inUse = false
				return
			}

			// For each newly issued certificate, we parse them to *X509.Certificates
			// and extract the data we want for our CertInfo struct.
			for i := 0; i < len(cert); i++ {
				func(loopIndex int) {
					// We decode the PEM to a *x509.Certificate,to access
					// the certificate's fields easily.
					x509ParsedCert, err := DecodePemsToX509(cert[loopIndex].PEM)
					if err != nil {
						fmt.Printf("Error parsing certs to x509: %v", err.Error())
						CTLogs[ind].inUse = false
						return
					}

					// Initialize structi with all fields
					certificate := CertInfo{
						CertIndex:    int(cert[loopIndex].Index),
						SerialNumber: x509ParsedCert[0].SerialNumber.String(),
						Domain:       x509ParsedCert[0].DNSNames,
						Certificate:  cert[loopIndex].PEM,
						Chain:        chain[loopIndex],
						Time:         time.Now().Hour(),
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
						for _, chainCert := range chain[loopIndex] {
							if uniqueCert.PEM == chainCert {
								uniqueIDs = append(uniqueIDs, uniqueCert.Index)
							}
						}
					}

					certificate.Chain = uniqueIDs
					certificate.Certificate = cert[loopIndex].PEM
					err = InsertCertIntoDB(*client, cancel, certificate)
					if err != nil {
						fmt.Printf("Error inserting cert into DB: %v", err.Error())
						CTLogs[ind].inUse = false
						return
					}
				}(i)
			}
			counter += currSTH - CTLogs[ind].currentIndex + 1
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
			CTLogs[ind].inUse = false
		}(index)
		index++
		elapsedTime += 0.5
		if DEBUG {
			fmt.Printf("New certs: %d.\n", counter)
			fmt.Printf("Certs per second: %.2f\n", float32(counter)/float32(time.Since(start).Seconds()))
		}
	}
}
