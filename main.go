package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"path"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

var certificateDirectory = flag.String("cert-dir", ".", "directory containing X509 certificates")
var pagerdutyToken = flag.String("pd-routing-key", "", "PagerDuty routing key")
var cloudwatchEventSuffix = flag.String("cwe-suffix", "", "Suffix for Cloudwatch Events")
var alarmSecondsToExpiry = flag.Int("seconds-to-expiry", 3600, "seconds from expiry after which alarms would fire")

func main() {
	flag.Parse()

	certificates, err := getCertificatesFromDir(*certificateDirectory)

	if err != nil {
		log.Fatalf("Unable to load certificates from path: %v, err: %v", *certificateDirectory, err)
	}

	log.Infof("found %v certificates in %v", len(certificates), *certificateDirectory)

	certificatesNearExpiry := getCertificatesNearExpiry(certificates, *alarmSecondsToExpiry)

	log.Infof("found %v certificates with less than %v seconds till expiry", len(certificatesNearExpiry), *alarmSecondsToExpiry)
	for _, c := range certificates {
		fmt.Printf("%v\n", c.Subject)
	}
}

func getCertificatesFromDir(certDir string) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate

	files, err := ioutil.ReadDir(certDir)
	if err != nil {
		log.Errorf("Failed to read directory: %v, error: %v", certDir, err)
		return nil, err
	}

	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".pem") && !file.IsDir() {
			p := path.Join(certDir, file.Name())
			certsInDir, err := loadCertificateFromFile(p)

			if err != nil {
				log.Warnf("Unable to open certificate %v, error: %v", p, err)
				continue
			}

			certificates = append(certificates, certsInDir...)
		}
	}
	return certificates, nil
}

func loadCertificateFromFile(p string) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate

	fileContent, err := ioutil.ReadFile(p)
	if err != nil {
		return nil, err
	}

	for {
		var block *pem.Block
		block, fileContent = pem.Decode(fileContent)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			log.Infof("Ignoring PEM block type %v in %v", block.Type, p)
			continue
		}

		parsed, err := x509.ParseCertificates(block.Bytes)
		if err != nil {
			log.Warnf("error parsing certificate in file: %v, error: %v", p, err)
			continue
		}

		certificates = append(certificates, parsed...)
	}
	return certificates, err
}

func getCertificatesNearExpiry(certificates []*x509.Certificate, maxSecondsTillExpiry int) []*x509.Certificate {
	var certificatesNearExpiry []*x509.Certificate
	for _, certificate := range certificates {
		now := time.Now()
		timeToExpiry := certificate.NotAfter.Sub(now)
		log.Infof(
			"certificate %v issued by %v has %s until expiry",
			certificate.Subject,
			certificate.Issuer.CommonName,
			timeToExpiry.String(),
		)
		if timeToExpiry.Seconds() < float64(maxSecondsTillExpiry) {
			certificatesNearExpiry = append(certificatesNearExpiry, certificate)
		}
	}
	return certificatesNearExpiry
}
