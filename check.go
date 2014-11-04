package main

import (
	"bytes"
	"crypto"
	_ "crypto/sha256"
	"crypto/tls"
	"crypto/x509" // used in requesting OCSP response
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"

	"code.google.com/p/go.crypto/ocsp"
)

var ocspUnauthorised = []byte{0x30, 0x03, 0x0a, 0x01, 0x06}
var ocspMalformed = []byte{0x30, 0x03, 0x0a, 0x01, 0x01}
var hasPort = regexp.MustCompile(`:\d+$`)

func checkError(err error) {
	if err == nil {
		return
	}

	fmt.Fprintf(os.Stderr, "[!] %v\n", err)
	os.Exit(1)
}

func parseCert(in []byte) (*x509.Certificate, error) {
	p, _ := pem.Decode(in)
	if p != nil {
		if p.Type != "CERTIFICATE" {
			return nil, errors.New("invalid certificate")
		}
		in = p.Bytes
	}

	return x509.ParseCertificate(in)
}

func fetchRemote(url string) (*x509.Certificate, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	in, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	return parseCert(in)
}

func main() {
	var certFile, issuerFile, ocspServer string
	flag.StringVar(&certFile, "f", "-", "certificate file")
	flag.StringVar(&issuerFile, "i", "", "issuing certificate")
	flag.StringVar(&ocspServer, "s", "", "OCSP server")

	flag.Parse()

	var (
		in           []byte
		err          error
		cert         *x509.Certificate
		ocspResponse *ocsp.Response
	)

	if certFile != "" && flag.NArg() == 0 {
		if certFile == "-" {
			in, err = ioutil.ReadAll(os.Stdin)
		} else {
			in, err = ioutil.ReadFile(certFile)
		}
		checkError(err)

		cert, err = parseCert(in)
		checkError(err)
	} else {
		if flag.NArg() == 0 {
			err = errors.New("no certificates supplied and no servers supplied")
		}

		server := flag.Arg(0)
		if !hasPort.MatchString(server) {
			server += ":443"
		}

		fmt.Println("fetching certificate from", server)

		conn, err := tls.Dial("tcp", server, nil)
		checkError(err)

		connState := conn.ConnectionState()
		peerChain := connState.PeerCertificates
		if len(peerChain) == 0 {
			err = errors.New("invalid certificate presented")
			checkError(err)
		}

		cert = peerChain[0]

		res := conn.OCSPResponse()
		if res != nil {
			fmt.Println("OCSP stapled response")
			ocspResponse, err = ocsp.ParseResponse(res, nil)
			checkError(err)
			showOCSPResponse(ocspResponse, nil)
			conn.Close()
			return
		}
		conn.Close()
	}

	ocspURLs := cert.OCSPServer
	if len(ocspURLs) == 0 {
		if ocspServer == "" {
			err = errors.New("no OCSP URLs found in cert, and none given via command line")
			checkError(err)
		}
		ocspURLs = []string{ocspServer}
	}

	var issuer *x509.Certificate
	for _, issuingCert := range cert.IssuingCertificateURL {
		issuer, err = fetchRemote(issuingCert)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			continue
		}
		break
	}

	if issuer == nil {
		err = errors.New("no issuing certificate could be found")
		checkError(err)
	}

	opts := ocsp.RequestOptions{
		Hash: crypto.SHA256,
	}
	ocspRequest, err := ocsp.CreateRequest(cert, issuer, &opts)
	checkError(err)

	for _, server := range ocspURLs {
		fmt.Println("sending OCSP request to", server)
		buf := bytes.NewBuffer(ocspRequest)
		resp, err := http.Post(server, "application/ocsp-request", buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			fmt.Fprintln(os.Stderr, "[!] invalid OCSP response from server", server)
			continue
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] failed to read response body: %s\n", err)
			continue
		}
		resp.Body.Close()

		if bytes.Equal(body, ocspUnauthorised) {
			fmt.Fprintf(os.Stderr, "[!] OCSP request unauthorised\n")
			continue
		}

		if bytes.Equal(body, ocspMalformed) {
			fmt.Fprintf(os.Stderr, "[!] OCSP server did not understand the request\n")
			continue
		}

		ocspResponse, err := ocsp.ParseResponse(body, issuer)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] invalid OCSP response from server\n")
			fmt.Fprintf(os.Stderr, "[!] %v\n", err)
			fmt.Fprintf(os.Stderr, "[!] Response is %x\n", body)
			ioutil.WriteFile("/tmp/ocsp.bin", body, 0644)
			continue
		}

		fmt.Println("OCSP response from", server)
		showOCSPResponse(ocspResponse, issuer)

		if issuerFile != "" && ocspResponse.Certificate != nil {
			p := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: ocspResponse.Certificate.Raw,
			}
			err = ioutil.WriteFile(issuerFile, pem.EncodeToMemory(p), 0644)
			checkError(err)
			fmt.Println("Wrote issuing certificate to", issuerFile)
		}
	}

}

func showOCSPResponse(res *ocsp.Response, issuer *x509.Certificate) {
	fmt.Printf("\tCertificate status: ")
	switch res.Status {
	case ocsp.Good:
		fmt.Println("good")
	case ocsp.Revoked:
		fmt.Println("revoked")
	case ocsp.ServerFailed:
		fmt.Println("server failed")
	case ocsp.Unknown:
		fmt.Println("unknown")
	default:
		fmt.Println("unknown response received from server")
	}

	fmt.Printf("\tCertificate serial number: %s\n", res.SerialNumber)
	fmt.Printf("\tStatus produced at %s\n", res.ProducedAt)
	fmt.Printf("\tCurrent update: %s\n", res.ThisUpdate)
	fmt.Printf("\tNext update: %s\n", res.NextUpdate)

	if res.Status == ocsp.Revoked {
		fmt.Printf("\tCertificate revoked at %s\n", res.RevokedAt)
	}

	if issuer != nil && res.Certificate == nil {
		fmt.Printf("\tSignature status: ")
		if err := res.CheckSignatureFrom(issuer); err == nil {
			fmt.Println("OK")
		} else {
			fmt.Printf("bad signature on response (%v)\n", err)
			fmt.Println("\t(maybe wrong OCSP issuer cert?)")
		}
	}
}
