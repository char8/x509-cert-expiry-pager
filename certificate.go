package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type certificate struct {
	filename string
	cert     *x509.Certificate
}

func (c *certificate) timeToExpiry() time.Duration {
	now := time.Now()
	return c.cert.NotAfter.Sub(now)
}

func (c *certificate) sha256Fingerprint() string {
	sum := sha256.Sum256(c.cert.Raw)
	return fmt.Sprintf("%x", sum)
}

func getCertificatesFromDir(certDir string) ([]certificate, error) {
	var certificates []certificate

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

			for _, cert := range certsInDir {
				certificates = append(certificates, certificate{file.Name(), cert})
			}
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

func getCertificatesNearExpiry(certificates []certificate, maxSecondsTillExpiry int) []certificate {
	var certificatesNearExpiry []certificate
	for _, certificate := range certificates {
		timeToExpiry := certificate.timeToExpiry()
		log.Infof(
			"certificate %v issued by %v has %s until expiry",
			certificate.cert.Subject,
			certificate.cert.Issuer.CommonName,
			timeToExpiry.String(),
		)
		if timeToExpiry.Seconds() < float64(maxSecondsTillExpiry) {
			certificatesNearExpiry = append(certificatesNearExpiry, certificate)
		}
	}
	return certificatesNearExpiry
}
