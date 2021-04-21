package main

import (
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	revoc "revocado"

	"golang.org/x/sync/semaphore"
	"context"
	"fmt"
	"log"
	"os"
	"time"
	"errors"
	"strconv"
)

const(
	unAuth = "ocsp: error from server: unauthorized"
	verErr = "bad OCSP signature: crypto/rsa: verification error"
	malFor = "ocsp: error from server: malformed"
	badSig = "bad OCSP signature: x509: signature algorithm specifies an ECDSA public key, but have public key of type *rsa.PublicKey"
	notOK = "Status for request no OK"
	other = "Other error"
)

var commonErrors  = []string{unAuth, verErr, malFor, badSig, notOK}
var dbUsername, dbPassword, dbIp, dbPort, dbName, dbChainCollection string

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
	dbChainCollection = os.Getenv("CERT_COLLECTION")
}

// Makes one insertion into MongoDB
func InsertCertIntoDB(client mongo.Client, cancel context.CancelFunc, cert CertInfo) error{
	collection := client.Database(dbName).Collection(fmt.Sprintf("%d", time.Now().Hour()))
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


func IterateBlock(blockTime int){
	// Establish connection to MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	uri := "mongodb://" + dbIp + ":" + dbPort
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))

	//disconnects the db when exiting main.
	// TODO: Make a WaitGroup so that all 
	// requests finish before disconnecting the 
	// DB.
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
	//findOptions.SetNoCursorTimeout(true)
	findOptions.SetBatchSize(5000)

	col := client.Database(dbName).Collection(fmt.Sprintf("%d", blockTime))

	// Passing bson.D{{}} as the filter matches all documents in the collection
	cur, err := col.Find(context.TODO(), bson.D{}, findOptions)
	if err != nil {
		fmt.Println("Error when collecting")
	}
	count :=0
	//Number of go-rutines that can run at the same time.
	//Aquisition is done withing the loop
	var sem = semaphore.NewWeighted(700)

	start := time.Now()
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

		//Artificial bottleneck to callOCSP
		//This is puts a cap on the number of connections to the DB
		ctxo := context.TODO()
		if err := sem.Acquire(ctxo, 1); err != nil {
			log.Printf("Failed to acquire semaphore: %v", err)
			break
		}
		go func() {
			defer sem.Release(1)
			//CALL METHOD TO CHECK OCSP
			erro := checkOCSP(elem, certIn.Chain[0], client, *col)
			if erro != nil{
				log.Println(erro)
			}
		}()
		count++
		if count % 100 == 0 {
			fmt.Printf("Reqs / s: %.2f\n", float64(count) / float64(time.Since(start).Seconds()))
		}
	}
	fmt.Printf("Count: %d, Count Success: %d, Hour: %d ", count, countS, blockTime)
	if err := cur.Err(); err != nil {
		//log.Fatal(err)
		fmt.Printf("%v\n", err.Error())
	}
	// Close the cursor once finished
	cur.Close(context.TODO())
}

var countS int = 0
func updateCount(){
	countS++
}

func contains(s []string, str string) int {
	for i, v := range s {
		if v == str {
			return i
		}
	}
	//numer 6 specifies that the error is of type "Other error"
	return 6
}

func checkOCSP(element bson.M, chainStringID string, client *mongo.Client, col mongo.Collection)(erro error){

	// convert id string to ObjectId
	objID, err := primitive.ObjectIDFromHex(chainStringID)
	if err != nil{
		return err
	}

	col2 := client.Database(dbName).Collection(dbChainCollection)
	var result ChainCertPem
	col2.FindOne(context.TODO(), bson.M{"_id": objID}).Decode(&result)

	ocspURL := element["OCSP"]
	elemID := element["_id"]
	rett := elemID.(primitive.ObjectID).Hex()

	b, err := DecodePemsToX509(result.PEM)
	if err != nil{
		//Checks if error is "standard error" or "Other error" and puts in a number between 0-6
		return AppendNewStatus(col, rett, time.Now(), "Err:"+ strconv.Itoa(contains(commonErrors, err.Error())))
	}

	cert := element["cert"]
	c, err := DecodePemsToX509(cert.(string))
	if err != nil{
		//Checks if error is "standard error" or "Other error" and puts in a number between 0-6
		return AppendNewStatus(col, rett, time.Now(), "Err:"+ strconv.Itoa(contains(commonErrors, err.Error())))
	}

	if len(b) == 0{
		return errors.New("Chain PEM was not found correctly (Len of chain PEM == 0)")
	}else if len(c) == 0{
		return errors.New("Cert PEM was not giving correct info (Len of cert PEM == 0)")
	}else {
		crl := element["CRL"]
		serial := element["serialNumber"]

		if ocspURL != nil{
			a, err :=revoc.GetOCSP(ocspURL.(string), &b[0], &c[0])
			if err != nil{
				//Checks if error is "standard error" or "Other error" and puts in a number between 0-6
				return AppendNewStatus(col, rett, time.Now(), "Err:"+ strconv.Itoa(contains(commonErrors, err.Error())))
			}
			updateCount()

			return AppendNewStatus(col, rett, time.Now(), a)			
		}else if crl != nil && crl != ""{
			inCRL, err := revoc.IsCertInCRL(crl.(string), serial.(string))
			if err != nil {
				//Checks if error is "standard error" or "Other error" and puts in a number between 0-6
				return AppendNewStatus(col, rett, time.Now(), "Err:"+ strconv.Itoa(contains(commonErrors, err.Error())))
			}
			if inCRL{
				fmt.Println("CRL WAS FOUND \n")
				return AppendNewStatus(col, rett, time.Now(), "Revoked")
			}
		}
		return errors.New("OCSP-URL not found!")
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
func AppendNewStatus(collection mongo.Collection, certID string, changeTime time.Time, status string) (erro error){

   // Read Once
    var res CertInfo
	theID, err2 := primitive.ObjectIDFromHex(certID)
	if err2 != nil{
		return err2
	}
	err := collection.FindOne(ctx, bson.M{"_id": theID}).Decode(&res)
	if err != nil{
        return err
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
			return err
		}

        _, err = collection.UpdateOne(ctx, bson.M{"_id": theID}, update)
        if err != nil{
			return err
		}
    }
	return nil
}

// Returns the corresponding PEM string for a chain cert ID
// from the DB
func getPEMfromID(certID string, client *mongo.Client) (string, error) {
    objectID, err := primitive.ObjectIDFromHex(certID)
    if err != nil {
        return "", err
    }
    var result bson.M
    col := client.Database(dbName).Collection(dbChainCollection)
    err = col.FindOne(context.Background(), bson.M{"_id": objectID}).Decode(&result)
    if err != nil {
        return "", err
    }

    if result["pem"] != nil {
        return fmt.Sprintf("%v", result["pem"]), nil
    }
    // If no cert found, return error
    return "", errors.New(fmt.Sprintf("No cert found with id %s.\n", certID))
}
