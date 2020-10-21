package main

import (
	"flag"

	log "github.com/sirupsen/logrus"
)

var certificateDirectory = flag.String("cert-dir", ".", "directory containing X509 certificates")
var pagerdutyRoutingKey = flag.String("pd-routing-key", "", "PagerDuty routing key")
var alarmSecondsToExpiry = flag.Int("seconds-to-expiry", 3600, "seconds from expiry after which alarms would fire")

func main() {
	flag.Parse()

	certificates, err := getCertificatesFromDir(*certificateDirectory)

	if err != nil {
		log.Fatalf("Unable to load certificates from path: %v, err: %v", *certificateDirectory, err)
	}

	log.Infof("found %v certificates in %v", len(certificates), *certificateDirectory)

	expiringCertificates := getCertificatesNearExpiry(certificates, *alarmSecondsToExpiry)

	log.Infof("found %v certificates with less than %v seconds till expiry", len(expiringCertificates), *alarmSecondsToExpiry)

	if *pagerdutyRoutingKey != "" {
		raisePagerdutyAlertsForCertificates(*pagerdutyRoutingKey, expiringCertificates)
	} else {
		log.Warnf("no PagerDuty routing key specified, skipping alarms")
	}
}
