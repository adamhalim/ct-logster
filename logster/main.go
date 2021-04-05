package main
//
import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/robfig/cron"

	"strings"
	"time"
	"github.com/CaliDog/certstream-go"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)


type CertInfo struct {
	CertIndex    int      		`bson:"certIndex"`
	SerialNumber string   		`bson:"serialNumber"`
	Domain       []string 		`bson:"domains"`
	OCSP         string   		`bson:"OCSP,omitempty"`
	CRL          string   		`bson:"CRL,omitempty"`
	CTlog        string   		`bson:"ctLog"`
 	Certificate  string   		`bson:"cert,omitempty"`
	Chain        []string 		`bson:"certChain,omitempty"`
	Time         int      		`bson:"Time"`
	Changes		 []StatusUpdate `bson:"Change"`
}

type StatusUpdate struct{
	Status 	string
	Time 	time.Time
}

type ChainCertPem struct {
	PEM string `bson:"pem"`
}

// Loads .env file
func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
		os.Exit(0)
	}
	dbUsername = os.Getenv("USERNAME")
	dbPassword = os.Getenv("PASSWORD")
	dbIp = os.Getenv("IP_ADDRESS")
	dbPort = os.Getenv("PORT")
}

func main(){
	fmt.Println("We actually ran")

	programName := "no args"
	if len(os.Args)>1{
		programName = os.Args[1]
		fmt.Println(programName)
	}

	if programName == "log"{
		logMain()

	}else if programName == "rev"{
		//cronjobs start
		log.Println("Create new cron")
		c := cron.New()
		//c.AddFunc("@every 0h05m", revocMain)

		// Start cron with one scheduled job
		log.Println("Start cron")
		c.Start()
		printCronEntries(c.Entries())
		revocMain()
		//time.Sleep(50 * time.Minute)
	}else{
		fmt.Println("Start with either log or rev")
	}
}

func revocMain(){
	fmt.Println("We running revocMain!")
	actualTime := time.Now()
	hour := actualTime.Hour()
	fmt.Println(hour)
	IterateBlock(21)
}

func logMain() {
	counter := 0
	// The false flag specifies that we want heartbeat messages.
	stream, errStream := certstream.CertStreamEventStream(false)

	// Establish connection to MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	uri := "mongodb://" + dbIp + ":" + dbPort
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))

	//disconnects the db when exiting main.
	defer func() {
		if err = client.Disconnect(ctx); err != nil {
			panic(err)
		}
	}()

	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = client.Ping(ctx, readpref.Primary())

	fmt.Println("Connected to MongoDB Server: " + dbIp + ".")

	for {
		//For more informaiton please see: https://pkg.go.dev/github.com/jmoiron/jsonq
		select {
		case jq := <-stream:
			_, err := jq.String("message_type")

			if err != nil {
				log.Printf("Error decoding jq string")
			}

			// Here, we grab all fields from the JQ response
			CertIndex, err := jq.Int("data", "cert_index")
			if err != nil {
				log.Printf("Error decoding jq cert index.")
			}

			SerialNumber, err := jq.String("data", "leaf_cert", "serial_number")
			if err != nil {
				log.Printf("Error decoding jq serial number.")
			}

			Domain, err := jq.ArrayOfStrings("data", "leaf_cert", "all_domains")
			if err != nil {
				log.Printf("Error decoding jq domains.")
			}

			OCSP, err := jq.String("data", "leaf_cert", "extensions", "authorityInfoAccess")

			if err != nil {
				log.Printf("Error decoding jq OCSP.")
			} else {
				if strings.Contains(OCSP, "OCSP - URI:") {
					tempStr := strings.Split(OCSP, "OCSP - URI:")
					if len(tempStr) > 1 {
						if strings.Contains(tempStr[1], "CA Issuers - URI:") {
							OCSP = (strings.Split(tempStr[1], "CA Issuers - URI:"))[0]
							OCSP = strings.Trim(OCSP, "\n")
						} else {
							OCSP = tempStr[1]
							OCSP = strings.Trim(OCSP, "\n")
						}
					}
				} else {
					fmt.Printf("Error: No OCSP URI found.")
				}
			}

			//Error prone due to inconsistent certificate format.
			CRL, err := jq.String("data", "leaf_cert", "extensions", "crlDistributionPoints")
			if err != nil {
				log.Printf("Error decoding jq CRL.")
			} else {
				CRL = strings.Split((strings.Split(CRL, "URI:")[1]), "\n")[0]
			}

			CTlog, err := jq.String("data", "source", "url")
			if err != nil {
				log.Print("No CT log URL found.")
			}

			// Fill struct with data
			cert := CertInfo{
				CertIndex:    CertIndex,
				SerialNumber: SerialNumber,
				Domain:       Domain,
				OCSP:         OCSP,
				CRL:          CRL,
				CTlog:        CTlog,
				Time:         time.Now().Hour(),
			}

			go func() {
				certificate, chain, err := DownloadCertsFromCT(CertIndex, CTlog)
				if err != nil {
					fmt.Printf("Error downloading certs: %q\n", err.Error())
					counter++
					return
				}

				var chainIDS []string
				// For the cert chain, we try to insert these
				// into the DB and append all associated chain certs
				// to []chainIDS.
				for _, entry := range chain {
					chainID, err := InsertChainCertIntoDB(*client, cancel, ChainCertPem{
						PEM: entry,
					})
					if err != nil {
						fmt.Printf("Error inserting chain cert into DB: %v", err.Error())
						return
					}
					chainIDS = append(chainIDS, chainID)
				}
				// Set the structs cert and chain parameters.
				// then push it to the DB
				cert.Certificate = certificate
				cert.Chain = chainIDS
				err = InsertCertIntoDB(*client, cancel, cert)
				if err != nil {
					fmt.Printf("Error inserting cert into DB: %v", err.Error())
				}
			fmt.Printf("Error counter: %d\n", counter)
			}()

			//dev-prints:
			/*
				fmt.Printf("Cert index: %d\n", CertIndex)
				fmt.Printf("Serial number: %s\n", SerialNumber)
				fmt.Printf("Domain: %s\n", Domain)
				fmt.Printf("CRL URL: %s\n", CRL)
				fmt.Printf("OCSP URL: %s\n", OCSP)
				fmt.Printf("CT log URL: %s\n", CTlog)
				fmt.Printf("\n")
			*/
		case err := <-errStream:
			log.Printf(err.Error())
		}
	}
}

func printCronEntries(cronEntries []cron.Entry) {
	log.Printf("Cron Info: %+v\n", cronEntries)
}
