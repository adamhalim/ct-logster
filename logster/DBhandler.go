package main

import (
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	revoc "../revocado"

	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)


var dbUsername, dbPassword, dbIp, dbPort, dbName, dbCollection, dbChainCollection string

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
	dbName = os.Getenv("DB")
	dbCollection = os.Getenv("MAIN_COLLECTION")
	dbChainCollection = os.Getenv("CERT_COLLECTION")
}

// Makes one insertion into MongoDB
func InsertCertIntoDB(client mongo.Client, cancel context.CancelFunc, cert CertInfo) error{

	collection := client.Database(dbName).Collection(dbCollection)
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	//Actual insert to MongoDB. Could possibly be done in batches for better performance
	_, err := collection.InsertOne(context.Background(), cert)
	if err != nil {
		return err
	}
	return nil
}

// Makes one insertion into MongoDB
func InsertChainCertIntoDB(client mongo.Client, cancel context.CancelFunc, chain ChainCertPem) (objectID string, err error) {

	// If, for any reason, the Chain certificate is empty,
	// we return.
	if chain.PEM == "" {
		fmt.Printf("Error inserting: Chain is empty.\n")
		return
	}
	// We check if the CertChainPem already is stored in the DB.
	chainInDB, err := isChainInDB(chain.PEM, &client)
	if err != nil {
		return "", err
	}
	if chainInDB != "" {
		fmt.Printf("Cert is already in DB\n")
		return chainInDB, nil
	}

	// For unique chain certs, we push them to our DB to the dbChainCollection
	collection := client.Database(dbName).Collection(dbChainCollection)
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	//Actual insert to MongoDB. Could possibly be done in batches for better performance
	res, err := collection.InsertOne(ctx, chain)
	if err != nil {
		return "", err
	}
	// If we are successful inserting, we return the
	id := res.InsertedID
	idString := id.(primitive.ObjectID).Hex()
	return idString, nil
}

// This will iterate though all certs in 
// database.collection and currently runs 
// GetCertChain() on all documents.
func IterateAllCerts() {
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

	col := client.Database(dbName).Collection(dbCollection)
	cursor, err := col.Find(context.TODO(), bson.D{})
	if err != nil {
		fmt.Println("Finding all documents ERROR:", err)
		defer cursor.Close(ctx)
	} else {
		// Creates a WaitGroup that will wait for all 
		// routines to finish before closing program
		var wg sync.WaitGroup
		for cursor.Next(ctx) {
			var result bson.M
			err := cursor.Decode(&result)
			// If there is a cursor.Decode error
			if err != nil {
				fmt.Println("cursor.Next() error:", err)
			} else {
				index := result["certIndex"]
				url := result["ctLog"]

				indexStr := fmt.Sprintf("%v", index)
				urlStr := fmt.Sprintf("%v", url)
				if url != "" {
					wg.Add(1)
					go func() {
						defer wg.Done()
						_, chain, err := GetChainCert(indexStr, urlStr)
						if err != nil {
							fmt.Printf("Error getting Cert Chain: %v", err.Error())
							return
						}
						certificates, err := DecodePemsToX509(chain)
						if err != nil {
							fmt.Printf("%s", err.Error())
						}
						if certificates == nil {
							fmt.Print("No certs decoded.\n")
						} else {

						}
					}()
				}
			}
		}
		wg.Wait()
	}
}

func IterateBlock(blockTime int){
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

	databases, err := client.ListDatabaseNames(ctx, bson.M{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(databases)

	// Pass these options to the Find method
	findOptions := options.Find()
	findOptions.SetLimit(1000)

	col := client.Database(dbName).Collection(dbCollection)

	// Passing bson.D{{}} as the filter matches all documents in the collection
	cur, err := col.Find(context.TODO(), bson.D{{"Time", blockTime}}, findOptions)
	if err != nil {
		fmt.Println("Error when collecting")
	}
	// Finding multiple documents returns a cursor
 	// Iterating through the cursor allows us to decode documents one at a time
	for cur.Next(context.TODO()) {
		// create a value into which the single document can be decoded
		var elem bson.M
		var certIn CertInfo

		err := cur.Decode(&elem)
		if err != nil {
			log.Fatal(err)
		}
		err = cur.Decode(&certIn)
		if err != nil {
			log.Fatal(err)
		}
		//CALL METHOD TO CHECK OCSP?
		checkOCSP(client, cancel, elem, certIn.Chain[0])
	}
	if err := cur.Err(); err != nil {
		log.Fatal(err)
	}

	// Close the cursor once finished
	cur.Close(context.TODO())
}

func checkOCSP(client *mongo.Client, cancel context.CancelFunc, element bson.M, chainStringID string){
	// convert id string to ObjectId
	objID, err := primitive.ObjectIDFromHex(chainStringID)
	if err != nil{
		log.Println("Invalid id")
	}

	col2 := client.Database(dbName).Collection(dbChainCollection)
	var result ChainCertPem
	col2.FindOne(context.TODO(), bson.M{"_id": objID}).Decode(&result)


	b, err := DecodePemsToX509(result.PEM)
	if err != nil{
		fmt.Println("B is fuk")
	}

	cert := element["cert"]
	c, err := DecodePemsToX509(cert.(string))
	if err != nil{
		fmt.Println("C is fuk")
	}

	ocspURL := element["OCSP"]
	elemID := element["_id"]
	if len(b) != 0 && len(c) != 0{
		if ocspURL != nil{
			a, err :=revoc.GetOCSP(ocspURL.(string), &b[0], &c[0])
			if err != nil{
				fmt.Println(err)
			}
			rett := elemID.(primitive.ObjectID).Hex()
			AppendNewStatus(client, cancel, rett, time.Now(), a)
		}
	}
}
// Checks whether a certificate already is in the cert chain DB.
// We run this for every cert in the chain to avoid saving duplicates.
// (A lot of certificates share chain certs)
func isChainInDB(chainCert string, client *mongo.Client) (objectID string, err error) {
	col := client.Database(dbName).Collection(dbChainCollection)
	cursor, err := col.Find(context.Background(), bson.M{"pem": chainCert})
	if err != nil {
		return "", err
	}

	// If we found something, we return the
	// Mongo object ID string
	for cursor.Next(context.Background()) {
		var result bson.M
		err := cursor.Decode(&result)
		if err != nil {
			fmt.Printf("Error decoding cert.\n")
			return "", err
		}
		// We convert the result to a ObjectID and return
		// the Object ID string
		objectID := result["_id"]
		stringObjectID := objectID.(primitive.ObjectID).Hex()
		return stringObjectID, nil
	}
	return "", nil
}
//status should only be: Good, Unknown, Revoked or Unexcpected.
//Unexcpeted will probably be handled earlier in code. But should still be handled here too
func AppendNewStatus(client *mongo.Client, cancel context.CancelFunc, certID string, changeTime time.Time, status string){
    collection := client.Database(dbName).Collection(dbCollection)
    ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
    defer cancel()

    // Read Once
    var res CertInfo
	theID, err2 := primitive.ObjectIDFromHex(certID)
	if err2 != nil{
		fmt.Println("error when converting certID to objectID")
	}
	err := collection.FindOne(ctx, bson.M{"_id": theID}).Decode(&res)
	if err != nil{
        fmt.Println("Error finding certID")
		//fmt.Printf("certID: %s, ", iD)
		return
    }

    var update bool = false
    s := len(res.Changes)

    if s > 0{
        lastElem := res.Changes[s-1]
        if lastElem.Status != status{
            newEntry := StatusUpdate{status, changeTime}
            res.Changes = append(res.Changes, newEntry)
            update = true
        }
    }else {
        if status != "Good" && status != ""{
            newEntry := StatusUpdate{status, changeTime}
            res.Changes = append(res.Changes, newEntry)
            update = true
        }
    }

    //Actual update to MongoDB. Could possibly be done in batches for better performance
    if update{
        //change, err := bson.Marshal(res)
		fmt.Printf("We updated certID: %s with new data!! \n\n", certID)
		update := bson.M{
        "$set": res,
		}
        if err != nil {
            fmt.Println("Error when using bson.Marshal.")
            fmt.Println(err)
        }

        _, err = collection.UpdateOne(ctx, bson.M{"_id": theID}, update)
        if err != nil{
            fmt.Println("Error when trying to update document")
            fmt.Println(err)
        }
    }
}
