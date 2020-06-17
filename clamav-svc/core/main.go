package main

import (
	"bytes"
	"fmt"
	"io"
	ioutil "io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dutchcoders/go-clamd"
)

var opts map[string]string

func init() {
	log.SetOutput(ioutil.Discard)
}

func home(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		isAuthorized, error := isCallerAuthorized(r)
		if error == nil && isAuthorized {
			c := clamd.NewClamd(opts["CLAMD_PORT"])
			version, err := c.Version()

			w.Header().Set("Content-Type", "application/json; charset=utf-8")

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			for versionstring := range version {
				responseJSON := fmt.Sprintf("{\"status\":\"OK\",\"version\": %#v}", versionstring.Raw)
				fmt.Fprint(w, responseJSON)
			}
		} else {
			http.Error(w, error.Error(), http.StatusForbidden)
		}

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func versionHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		isAuthorized, error := isCallerAuthorized(r)
		if error == nil && isAuthorized {
			c := clamd.NewClamd(opts["CLAMD_PORT"])
			version, err := c.Version()
			w.Header().Set("Content-Type", "application/json; charset=utf-8")

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			for versionstring := range version {
				responseJSON := fmt.Sprintf("{\"version\": %#v}", versionstring.Raw)
				fmt.Fprint(w, responseJSON)
			}
		} else {
			http.Error(w, error.Error(), http.StatusForbidden)
		}

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func signatureHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		isAuthorized, error := isCallerAuthorized(r)
		if error == nil && isAuthorized {
			var hash = r.FormValue("hash")
			var hmachash = r.FormValue("hmac")

			var result = validateMac(hash, hmachash)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")

			if hash != "" && hmachash != "" {
				w.WriteHeader(http.StatusOK)
				responseJSON := fmt.Sprintf("{\"hash\":\"%s\",\"check\": \"%t\"}", hash, result)
				fmt.Fprint(w, responseJSON)

			} else {
				w.WriteHeader(http.StatusBadRequest)
			}
		} else {
			http.Error(w, error.Error(), http.StatusForbidden)
		}

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

//This is where the action happens.
func scanHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	//POST takes the uploaded file(s) and saves it to disk.
	case "POST":
		isAuthorized, error := isCallerAuthorized(r)
		if error == nil && isAuthorized {
			c := clamd.NewClamd(opts["CLAMD_PORT"])
			//get the multipart reader for the request.
			reader, err := r.MultipartReader()

			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			var hash string

			//copy each part to destination.
			for {
				part, err := reader.NextPart()
				if err == io.EOF {
					break
				}

				if part.FormName() == "hash" {
					buf := new(bytes.Buffer)
					buf.ReadFrom(part)
					hash = buf.String()
				} else if part.FormName() == "file" {

					//if part.FileName() is empty, skip this iteration.
					if part.FileName() == "" {
						continue
					}

					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					fmt.Printf(time.Now().Format(time.RFC3339) + " Started scanning: " + part.FileName() + "\n")
					var abort chan bool
					response, err := c.ScanStream(part, abort)

					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
					}

					for s := range response {

						respJson := fmt.Sprintf("{ \"Status\": \"%s\", "+
							"\"Description\": \"%s\" , "+
							"\"Path\": \"%s\" , "+
							"\"Hash\": \"%s\" , "+
							"\"Signature\": \"%s\" "+
							"}", s.Status, s.Description, s.Path, hash, genHmac(hash))
						switch s.Status {
						case clamd.RES_OK:
							w.WriteHeader(http.StatusOK)
						case clamd.RES_FOUND:
							w.WriteHeader(http.StatusNotAcceptable)
						case clamd.RES_ERROR:
							w.WriteHeader(http.StatusBadRequest)
						case clamd.RES_PARSE_ERROR:
							w.WriteHeader(http.StatusPreconditionFailed)
						default:
							w.WriteHeader(http.StatusNotImplemented)
						}
						fmt.Fprint(w, respJson)
						fmt.Printf(time.Now().Format(time.RFC3339)+" Scan result for: %v, %v\n", part.FileName(), s)
					}
					fmt.Printf(time.Now().Format(time.RFC3339) + " Finished scanning: " + part.FileName() + "\n")
					break
				}
			}

		} else {
			http.Error(w, error.Error(), http.StatusForbidden)

		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func waitForClamD(port string, times int) {
	clamdTest := clamd.NewClamd(port)
	clamdTest.Ping()
	version, err := clamdTest.Version()

	if err != nil {
		if times < 30 {
			fmt.Printf("clamD not running, waiting times [%v]\n", times)
			time.Sleep(time.Second * 4)
			waitForClamD(port, times+1)
		} else {
			fmt.Printf("Error getting clamd version: %v\n", err)
			os.Exit(1)
		}
	} else {
		for version_string := range version {
			fmt.Printf("Clamd version: %#v\n", version_string.Raw)
		}
	}
}

func main() {

	opts = make(map[string]string)

	for _, e := range os.Environ() {
		pair := strings.Split(e, "=")
		opts[pair[0]] = pair[1]
	}

	if opts["CLAMD_PORT"] == "" {
		opts["CLAMD_PORT"] = "tcp://127.0.0.1:3310"
	}

	fmt.Printf("Starting clamav rest bridge\n")
	fmt.Printf("Connecting to clamd on %v\n", opts["CLAMD_PORT"])
	waitForClamD(opts["CLAMD_PORT"], 1)

	fmt.Printf("Connected to clamd on %v\n", opts["CLAMD_PORT"])

	http.HandleFunc("/scan", scanHandler)
	http.HandleFunc("/version", versionHandler)
	http.HandleFunc("/sigverify", signatureHandler)
	http.HandleFunc("/", home)

	//Listen on port PORT
	if opts["PORT"] == "" {
		opts["PORT"] = "9000"
	}
	fmt.Printf("Listening on port " + opts["PORT"])
	http.ListenAndServe(":"+opts["PORT"], nil)
}
