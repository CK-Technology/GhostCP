# Mail Authentication (SPF, DKIM, DMARC)

Deliverability depends on the three sender-authentication records. Because GhostCP
manages [DNS](../dns/) and mail together, it can publish these records in the same
zone it serves.

## SPF

A TXT record listing the hosts allowed to send for the domain:

```
example.com.  IN  TXT  "v=spf1 mx -all"
```

## DKIM

GhostCP generates a DKIM key per mail domain (size set by `DKIM_KEY_SIZE`,
default 2048) and publishes the public key as a TXT record at the configured
selector:

```
<selector>._domainkey.example.com.  IN  TXT  "v=DKIM1; k=rsa; p=<public-key>"
```

Postfix signs outbound mail with the private key.

## DMARC

A policy record telling receivers how to handle SPF/DKIM failures and where to
send reports:

```
_dmarc.example.com.  IN  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
```

## Status

DKIM key sizing is configurable and the DNS subsystem can publish these records.
Automatic generation and publication as part of mail-domain provisioning is
staged with the rest of the mail stack — see the
[status table](../../README.md#status).
