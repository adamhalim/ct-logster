# ct-logster

This repository contains the tools for collecting newly issued x509 certificates from [Certificate Transparency](https://certificate.transparency.dev/https://certificate.transparency.dev/) logs, as well as performing OCSP & CRL revocation checks on the certficates.

## logster

Logster is the tool that is used to monitor CT logs and fetch all newly issued certificates.
The tool can listen to any amount of CT logs which reside in `logs.txt`. 
Each log URL is separated by a new line, and should not start with https://.

<details>
<summary>Example logs.txt file</summary>
  
```
yeti2022.ct.digicert.com/log
yeti2023.ct.digicert.com/log
ct.googleapis.com/logs/argon2021
ct.googleapis.com/logs/argon2022
ct.googleapis.com/logs/argon2023
```
</details>


From each newly issued certificate that is logged, the certificate PEM, as well as its chain is downloaded and stored in a MongoDB.

**NOTE**: A certificate can be logged to multiple CT logs.
This tool does not take this into account and does NOT omit certificates that already have been stored in the database.
As such, multiple entires of the same certificate will make it into the database.


## revocado

Revocado is used to check the recovation statuses of certificates logged by logster.
The primary way of checking revocation statuses is through OCSP requests.
From these OCSP requests, we extract the revocation status, the revocation reason and the time of revocation.
If OCSP isn't available, we perform a CRL check instead.
The result from a CRL check is a binary yes/no, depending on if the certificate is in the CRL or not.

### Error codes

A list of common error responses for OCSP requests are defined in `DBhandler.go` and have a corresponding error code:

```
unAuth  0
verErr  1
malFor  2 
badSig  3 
notOK   4
tOut    5
other   7
```

## Setup

The tool is written in [Go](https://go.dev/), and needs an installation of Go to compile.
To compile the program, simply run `go build`. 

The tool uses MongoDB for data storage and the configuration is stored in a `.env` file.

<details>
<summary>Example .env file</summary>
  
```
IP_ADDRESS="localhost"
PORT="27017"
DB="logs"
CERT_COLLECTION="chains"
USERNAME="username"
PASSWORD="passwd"
```
</details>

### Performance
Depending on hardware used, the amount of parallell revocation checks that can be performed will differ.
To control how many requests are ran concurrently, the semaphore `sem` in `DBhandler.go` is used.
Feel free to play around with this to find a good value for your system.

### cron

To set up periodic revocation checking, cron jobs can be used to run the tool every hour. To set up a crontab, run `crontab -e` and put in the following:

`0 * * * * /path/to/ct-logster/logster/logster rev >> /path/to/ct-logster/logster/output.txt`

This will run a revocation check every hour and append the output to `output.txt`.

### Data structure
The data that is stored in the database is the struct `CertInfo` in `logster.go`.
Feel free to remove/add fields to suit your needs.
```go
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
```

## Running
To run the collection tool, simply run `logster log`. Do this for however long you wish to collect newly issued certificates.
[timeout](https://man7.org/linux/man-pages/man1/timeout.1.html) can be used to set a time limit for the collection.
For example, `timeout 2d logster log` will terminate the program after 2 days.
Revocation checking can be performed in parallell with certificate collection, which is done easily by setting up cron jobs.

# Notes
Were you to use our code, dataset, or parts of it in your work, we kindly ask that you reference the following paper in your publication:
Adam Halim, Max Danielsson, Martin Arlitt and Niklas Carlsson, "Temporal Analysis of X.509 Revocations and their Statuses", *Proc. International Workshop on Traffic Measurements for Cybersecurity (WTMC)*, June 2022
