package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

var (
	flagCa      bool
	flagCert    bool
	flagSign    bool
	flagOutPem  string
	flagOutKey  string
	flagInCAPem string
	flagInCAKey string
)

type ca struct {
	ca      x509.Certificate
	cert    []byte
	PubKey  *rsa.PublicKey
	PrivKey *rsa.PrivateKey
	certPem *bytes.Buffer
	privPem *bytes.Buffer
}

type cert struct {
	cert    []byte
	certPem *bytes.Buffer
	privPem *bytes.Buffer
}

type certificateField struct {
	Country            []string
	Locality           []string
	Province           []string
	Organization       []string
	OrganizationalUnit []string
	StreetAddress      []string
	PostalCode         []string
	CommonName         string
	DNSNames           []string
	EmailAddresses     []string
	IPAddresses        []net.IP
	URIs               []*url.URL
	NotAfter           int
}

func init() {
	flag.BoolVar(&flagCa, "ca", false, "generate ca cert.")
	flag.BoolVar(&flagCert, "cert", false, "generate cert.")
	flag.BoolVar(&flagSign, "sign-ca", false, "sign certificate with ca")
	flag.StringVar(&flagOutPem, "outpem", "", "output pem file")
	flag.StringVar(&flagOutKey, "outkey", "", "output key file")
	flag.StringVar(&flagInCAPem, "inca", "", "input pem file")
	flag.StringVar(&flagInCAKey, "inkey", "", "input key file")
}

func main() {

	// Manipulate flag usage message
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of :\n")
		flag.PrintDefaults()
		fmt.Printf("For more information: https://github.com/AbdulmelikKalkan/gece\n")
	}

	// Parse parses flag definitions from the argument list
	flag.Parse()

	var caCertificate ca
	var selfSignCertificate cert

	switch {
	case flagCa && !flagCert && !flagSign:
		// generate certificate authority
		caCertificate.generateCA()
		writeCert(caCertificate.certPem.Bytes(), caCertificate.privPem.Bytes())
	case flagCa && flagCert:
		usageInfo()
		os.Exit(1)
	case flagCert && !flagSign:
		// generate certificate
		selfSignCertificate.generateCert()
		writeCert(selfSignCertificate.certPem.Bytes(), selfSignCertificate.privPem.Bytes())
	case flagCert && flagSign && len(flag.Args()) == 0:
		fmt.Println("Generate cert and sign ca which is generated")
		caCertificate.generateCA()
		selfSignCertificate.generateCertSignCA(caCertificate.ca, caCertificate.PrivKey)
		writeCert(selfSignCertificate.certPem.Bytes(), selfSignCertificate.privPem.Bytes())
	case flagCert && flagSign && len(flag.Args()) > 0:
		fmt.Println("Generate cert and sign ca which is given with parameters")

		if flagInCAPem != "" && flagInCAKey != "" {
			caPem, err := os.ReadFile(flagInCAPem)
			checkErr(err)
			caKey, err := os.ReadFile(flagInCAKey)
			checkErr(err)
			blockCA, _ := pem.Decode(caPem)
			blockKey, _ := pem.Decode(caKey)
			caCert, err := x509.ParseCertificate(blockCA.Bytes)
			checkErr(err)
			caPrivateKey, err := x509.ParsePKCS1PrivateKey(blockKey.Bytes)
			checkErr(err)
			selfSignCertificate.generateCertSignCA(*caCert, caPrivateKey)
			writeCert(selfSignCertificate.certPem.Bytes(), selfSignCertificate.privPem.Bytes())
		} else {
			panic("No input files")
		}

	default:
		usageInfo()
		os.Exit(0)
	}

}

func (ca *ca) generateCA() {
	fmt.Println("Generate CA Certificate")
	var caField certificateField
	caField.setCA()

	caCert := &x509.Certificate{
		SerialNumber: getRandSerialNumber(),
		Subject: pkix.Name{
			Country:            caField.Country,
			Province:           caField.Province,
			Locality:           caField.Locality,
			Organization:       caField.Organization,
			OrganizationalUnit: caField.OrganizationalUnit,
			StreetAddress:      caField.StreetAddress,
			PostalCode:         caField.PostalCode,
			CommonName:         caField.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(caField.NotAfter, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		DNSNames:              caField.DNSNames,
		EmailAddresses:        caField.EmailAddresses,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate private key: %s" + err.Error())
	}
	caPub := &caPrivKey.PublicKey

	caBytes, err := x509.CreateCertificate(rand.Reader, caCert, caCert, caPub, caPrivKey)
	if err != nil {
		log.Fatalf("failed to create ca cert: %s", err)
	}

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	ca.ca = *caCert
	ca.cert = caBytes
	ca.PrivKey = caPrivKey
	ca.PubKey = caPub
	ca.certPem = caPEM
	ca.privPem = caPrivKeyPEM
}

func (cert *cert) generateCert() {
	fmt.Println("Generating Self-Sign Certificate")
	var caField certificateField
	caField.setCA()

	certificate := x509.Certificate{
		SerialNumber: getRandSerialNumber(),
		Subject: pkix.Name{
			Country:            caField.Country,
			Province:           caField.Province,
			Locality:           caField.Locality,
			Organization:       caField.Organization,
			OrganizationalUnit: caField.OrganizationalUnit,
			StreetAddress:      caField.StreetAddress,
			PostalCode:         caField.PostalCode,
			CommonName:         caField.CommonName,
		},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(caField.NotAfter, 0, 0),
		SubjectKeyId:   []byte{1, 2, 3, 4, 5},
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:       x509.KeyUsageDigitalSignature,
		IPAddresses:    caField.IPAddresses,
		DNSNames:       caField.DNSNames,
		EmailAddresses: caField.EmailAddresses,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("failed to generate key: %s", err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &certificate, &certificate, &certPrivKey.PublicKey, certPrivKey)
	if err != nil {
		log.Fatalf("Failed to create cert: %s", err)
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivPEM := new(bytes.Buffer)
	pem.Encode(certPrivPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	cert.cert = certBytes
	cert.certPem = certPEM
	cert.privPem = certPrivPEM
}

func (cert *cert) generateCertSignCA(c x509.Certificate, k *rsa.PrivateKey) {
	var caField certificateField
	caField.setCA()

	certificate := x509.Certificate{
		SerialNumber: getRandSerialNumber(),
		Subject: pkix.Name{
			Country:            caField.Country,
			Province:           caField.Province,
			Locality:           caField.Locality,
			Organization:       caField.Organization,
			OrganizationalUnit: caField.OrganizationalUnit,
			StreetAddress:      caField.StreetAddress,
			PostalCode:         caField.PostalCode,
			CommonName:         caField.CommonName,
		},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(caField.NotAfter, 0, 0),
		SubjectKeyId:   []byte{1, 2, 3, 4, 5},
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:       x509.KeyUsageDigitalSignature,
		IPAddresses:    caField.IPAddresses,
		DNSNames:       caField.DNSNames,
		EmailAddresses: caField.EmailAddresses,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("failed to generate key: %s", err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &certificate, &c, &certPrivKey.PublicKey, k)
	if err != nil {
		log.Fatalf("Failed to create cert: %s", err)
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivPEM := new(bytes.Buffer)
	pem.Encode(certPrivPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	cert.cert = certBytes
	cert.certPem = certPEM
	cert.privPem = certPrivPEM
}

func (c *certificateField) setCA() {
	scanner := bufio.NewScanner(os.Stdin)

	v := reflect.ValueOf(*c)
	typeOfS := v.Type()
	for i := 0; i < v.NumField(); i++ {
		switch typeOfS.Field(i).Name {
		case "Country":
			fmt.Printf("Country: ")
			scanner.Scan()
			c.Country = []string{scanner.Text()}
		case "Province":
			fmt.Printf("State or Province: ")
			scanner.Scan()
			c.Province = []string{scanner.Text()}
		case "Locality":
			fmt.Printf("Locality: ")
			scanner.Scan()
			c.Locality = []string{scanner.Text()}
		case "Organization":
			fmt.Printf("Organization: ")
			scanner.Scan()
			c.Organization = []string{scanner.Text()}
		case "OrganizationalUnit":
			fmt.Printf("OrganizationalUnit: ")
			scanner.Scan()
			c.OrganizationalUnit = []string{scanner.Text()}
		case "StreetAddress":
			fmt.Printf("StreetAddress: ")
			scanner.Scan()
			c.StreetAddress = []string{scanner.Text()}
		case "PostalCode":
			fmt.Printf("PostalCode: ")
			scanner.Scan()
			c.PostalCode = []string{scanner.Text()}
		case "CommonName":
			fmt.Printf("CommonName: ")
			scanner.Scan()
			c.CommonName = scanner.Text()
		case "DNSNames":
			fmt.Printf("DNSNames: use comma for multiple values like localhost,example.com\n-->: ")
			scanner.Scan()
			c.DNSNames = strings.Split(scanner.Text(), ",")
		case "EmailAddresses":
			fmt.Printf("EmailAddresses: ")
			scanner.Scan()
			c.EmailAddresses = []string{scanner.Text()}
		case "IPAddresses":
			if flagCert {
				fmt.Printf("IPAddresses: use comma for multiple values like 127.0.0.1,192.168.1.1\n-->: ")
				scanner.Scan()
				var ips []net.IP
				ipSlice := strings.Split(scanner.Text(), ",")
				for _, v := range ipSlice {
					ips = append(ips, net.ParseIP(v))
				}
				c.IPAddresses = ips
			}
		case "URIs":
			if flagCert {
				fmt.Printf("URIs: use comma for multiple values like https://example.com,https://example.dev\n-->: ")
				scanner.Scan()
				var urls []*url.URL
				urlSlice := strings.Split(scanner.Text(), ",")
				for _, v := range urlSlice {
					u, _ := url.Parse(v)
					urls = append(urls, u)
				}
				c.URIs = urls
			}
		case "NotAfter":
			fmt.Printf("NotAfter: ")
			scanner.Scan()
			c.NotAfter, _ = strconv.Atoi(scanner.Text())
		}
	}
}

// getRandSerialNumber generates random serial number for certificate
func getRandSerialNumber() *big.Int {

	// Create slice of byte and append random byte
	var byteSlice []byte
	for i := 0; i < 20; i++ {
		n, _ := rand.Int(rand.Reader, big.NewInt(255))
		byteSlice = append(byteSlice, byte(n.Int64()))
	}
	// return slice of bytes as a big integer
	return big.NewInt(0).SetBytes(byteSlice)
}

func writeCert(c []byte, k []byte) {
	if flagOutPem != "" {
		err := os.WriteFile(flagOutPem, c, 0644)
		checkErr(err)
	}
	if flagOutKey != "" {
		err := os.WriteFile(flagOutKey, c, 0644)
		checkErr(err)
	}
}

func checkErr(e error) {
	if e != nil {
		panic(e)
	}
}

func usageInfo() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage of :\n")
	flag.PrintDefaults()
	fmt.Printf("For more information: https://github.com/AbdulmelikKalkan/gece\n")
}
