package main

import (
	"fmt"
	"os"

	"github.com/PagerDuty/go-pagerduty"
	log "github.com/sirupsen/logrus"
)

func raisePagerdutyAlertsForCertificates(routingKey string, expiringCertificates []certificate) {
	hostname, _ := os.Hostname()
	for _, certificate := range expiringCertificates {
		event := getPagerdutyEventForCert(routingKey, hostname, certificate)
		resp, err := pagerduty.ManageEvent(event)
		if err != nil {
			log.Errorf("unable to post expiry alert for %v to pagerduty, error: %v", certificate.filename, err)
			continue
		}

		if len(resp.Errors) == 0 {
			log.Infof("PagerDuty response: %v, message: %v", resp.Status, resp.Message)
		} else {
			log.Errorf("PagerDuty response: %v, message: %v, errors: %v", resp.Status, resp.Message, resp.Errors)
		}
	}
}

func getPagerdutyEventForCert(routingKey string, hostname string, cert certificate) pagerduty.V2Event {
	daysToExpiry := cert.timeToExpiry().Hours() / 24

	severity := "warning"
	if cert.timeToExpiry().Hours() < 24 {
		severity = "critical"
	}

	return pagerduty.V2Event{
		RoutingKey: routingKey,
		Action:     "trigger",
		DedupKey:   fmt.Sprintf("%v_%v", hostname, cert.filename),
		Client:     "x509-cert-expiry-pager",
		ClientURL:  "github.com/char8/x509-cert-expiry-pager",
		Payload: &pagerduty.V2Payload{
			Summary:  fmt.Sprintf("certificate %v is %.2f days from expiring", cert.filename, daysToExpiry),
			Source:   hostname,
			Severity: severity,
			Group:    fmt.Sprintf("certificates monitored on %v", hostname),
			Class:    "x509 certificate expiry",
			Details: &struct {
				Subject           string
				Issuer            string
				Filename          string
				FingerprintSha256 string
			}{
				Subject:           cert.cert.Subject.String(),
				Issuer:            cert.cert.Issuer.String(),
				Filename:          cert.filename,
				FingerprintSha256: cert.sha256Fingerprint(),
			},
		},
	}
}
