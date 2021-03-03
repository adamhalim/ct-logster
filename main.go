package main

import (
	"github.com/CaliDog/certstream-go"
	"fmt"
	"log"
	"strings"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"os"
	"context"
	"time"
)

type CertInfo struct {
	CertIndex		int32
	SerialNumber	string
	Domain			[]string
	OCSP			string
	CRL				[]string
}

var dbUsername, dbPassword, dbIp, dbPort string;

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
	certIndex int, serialNumber string, domain []string, OCSP string, CRL string) {

	collection := client.Database("dev").Collection("certificates")
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	//Actual insert to MongoDB. Could possibly be done in batches for better performance
	_, err := collection.InsertOne(ctx, bson.D{
		{"certIndex", certIndex},
		{"serialNumber", serialNumber},
		{"Domain", domain},
		{"OCSP", OCSP },
		{"CRL", CRL},
		{"Time", time.Now().Hour()},
	})
	if (err != nil) {
		fmt.Print("Error inserting.")
	}
}

func main() {
	// The false flag specifies that we want heartbeat messages.
	stream, errStream := certstream.CertStreamEventStream(false);

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
			_, err := jq.String("message_type");

			if err != nil {	log.Printf("Error decoding jq string"); }
			
			// Here, we grab all fields from the JQ response
			CertInfo, err := jq.Int("data", "cert_index");
			if err != nil {	log.Printf("Error decoding jq cert index."); }

			SerialNumber, err := jq.String("data", "leaf_cert","serial_number")
			if err != nil {	log.Printf("Error decoding jq serial number."); }

			Domain, err := jq.ArrayOfStrings("data", "leaf_cert", "all_domains");
			if err != nil {	log.Printf("Error decoding jq domains."); }

			OCSP, err := jq.String("data", "leaf_cert", "extensions", "authorityInfoAccess");

			if err != nil {
				log.Printf("Error decoding jq OCSP.");
			} else {
				if(strings.Contains(OCSP, "OCSP - URI:")) {
				// Sometimes, the OCSP - URI and CA Issuers - URI were reversed.
				// This is a poor, hack:y attempt to try and grab only the line that
				// is the OCSP URI
				OCSP = strings.Split(OCSP, "OCSP - URI:")[1];
				OCSP = (strings.Split(OCSP, "\n")[0]);
				} else 	if (strings.Contains(OCSP, "CA Issuers - URI:")) {
					if(strings.Contains(OCSP, strings.Split(OCSP, "CA Issuers - URI:")[0])) {
						OCSP = strings.Split(OCSP, "CA Issuers - URI:")[1];
					} else {
						OCSP = strings.Split(OCSP, "CA Issuers - URI:")[0];
					}
				}				
			}			

			//Error prone due to inconsistent certificate format.
			CRL, err := jq.String("data", "leaf_cert", "extensions", "crlDistributionPoints")
			if err != nil {
				log.Printf("Error decoding jq CRL.");
			} else {
				CRL = strings.Split((strings.Split(CRL, "URI:")[1]), "\n")[0];
			}

			//ctx and cancel given from beginning of main.
			insertIntoDB(*client, ctx, cancel, CertInfo, SerialNumber, Domain, OCSP, CRL);


			//dev-prints:
			fmt.Printf("Cert index: %d\n", CertInfo);
			fmt.Printf("Serial number: %s\n", SerialNumber);
			fmt.Printf("Domain: %s\n", Domain);
			fmt.Printf("CRL URL: %s\n", CRL);
			fmt.Printf("OCSP URL: %s\n", OCSP);
			fmt.Printf("\n");

		case err := <-errStream:
			log.Printf(err.Error());
		}
	}
}
