# x509-cert-expiry-pager

Sometimes you have a really old server somewhere that's got some X509 certificates on it, and you always forget when they expire. This simple hacky tool is intended to run on a daily timer and alarm you on PagerDuty when certificates are near expiry.

## Usage

```
$ x509-cert-expiry-pager -cert-dir <PATH> -pd-routing-key <ROUTING_KEY> -seconds-to-expiry <SECONDS>
```

* **-cert-dir**: path to the directory containing X509 certs in PEM format (defaults to current working dir)
* **-pd-routing-key**: A PagerDuty Events API V2 integration key
* **-seconds-to-expiry**: An incident will be raised for each certificate if it expires sooner than this

## Deploying

1. Create a new PD service and V2 Integration
2. Via your favourite config management:
    1. template a SystemD timer with the required parameters (see `example` directory)
    2. Install this binary into your PATH

To avoid checking in the PD routing key into Git, consider using [confd](https://github.com/kelseyhightower/) or similar to template it in from a secret store.


## TODO

* Integrate Cloudwatch Events or SNS to remove reliance on PagerDuty
