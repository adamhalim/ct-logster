package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/CaliDog/certstream-go"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

type CertInfo struct {
	CertIndex    int      `bson:"certIndex"`
	SerialNumber string   `bson:"serialNumber"`
	Domain       []string `bson:"domains"`
	OCSP         string   `bson:"OCSP,omitempty"`
	CRL          string   `bson:"CRL,omitempty"`
	CTlog        string   `bson:"ctLog"`
	Certificate  string   `bson:"cert,omitempty"`
	Chain        string   `bson:"certChain,omitempty"`
}

var dbUsername, dbPassword, dbIp, dbPort string

// Loads .env file
func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	dbUsername = os.Getenv("USERNAME")
	dbPassword = os.Getenv("PASSWORD")
	dbIp = os.Getenv("IP_ADDRESS")
	dbPort = os.Getenv("PORT")
}

// Makes one insertion into MongoDB
func insertIntoDB(client mongo.Client, ctx context.Context, cancel context.CancelFunc,
	cert CertInfo) {

	collection := client.Database("dev").Collection("certTestThree")
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	//Actual insert to MongoDB. Could possibly be done in batches for better performance
	_, err := collection.InsertOne(ctx, cert)
	if err != nil {
		fmt.Print("Error inserting.")
	}
}

func main() {
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
			}

			go func() {
				if CTlog != "" {
					chain, err := DownloadCertFromCT(CertIndex, CTlog)
					if err != nil {
						fmt.Printf("ErrorSWAG: %q\n", err.Error())
						counter++
					}
					if chain != "" {
					}
					cert.Chain = chain
					insertIntoDB(*client, ctx, cancel, cert)

				} else {
					insertIntoDB(*client, ctx, cancel, cert)
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
