# ct_logster

This project consists of two parts: logster and revocado.

## logster

Logster is a tool that is used to monitor CT logs and fetch all newly issued certificates.
The tool can listen to any amount of CT logs, currently controlled by the slice `ctLogURLs` in `logster.go`

From each newly issued certificate, the cert.pem as well as its chain is downloaded and stored in a MongoDB.

## revocado (wip)

Revocado is used to check the recovation statuses of certificates logged by logster.
The primary way of checking revocation statuses is through OCSP requests.
From these OCSP requests, we extract the revocation status, the revocation reason and the time of revocation.
If OCSP isn't available, we perform a CRL check instead.
The result from a CRL check is a binary yes/no, depending on if the certificate is in the CRL or not.


## Dependencies:

* `go get github.com/CaliDog/certstream-go`
* `go get github.com/google/certificate-transparency-go`
* `go get github.com/joho/godotenv`
* `go get github.com/golang/protobuf/ptypes`
* `go get github.com/golang/glog`
* `go get go.mongodb.org/mongo-driver/mongo`
* `go get golang.org/x/net/context/ctxhttp`