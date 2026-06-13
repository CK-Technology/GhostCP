# Zones & Records

## Zones

A zone is an authoritative DNS domain GhostCP manages. Zones are stored in
PostgreSQL and rendered/pushed to the active provider driver.

List and create zones:

```bash
# list
curl http://localhost:8080/api/v1/dns \
  -H 'Authorization: Bearer <token>'

# create
curl -X POST http://localhost:8080/api/v1/dns \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com","provider":"local"}'
```

Get a single zone:

```bash
curl http://localhost:8080/api/v1/dns/{id} \
  -H 'Authorization: Bearer <token>'
```

## Records

Records belong to a zone. Standard types are supported (A, AAAA, CNAME, MX, TXT,
NS, SRV, CAA, …).

```bash
# list records in a zone
curl http://localhost:8080/api/v1/dns/{id}/records \
  -H 'Authorization: Bearer <token>'

# create a record
curl -X POST http://localhost:8080/api/v1/dns/{id}/records \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"name":"www","type":"A","content":"203.0.113.10","ttl":3600}'
```

## Syncing

After editing records, push the zone to its provider:

```bash
curl -X POST http://localhost:8080/api/v1/dns/{id}/sync \
  -H 'Authorization: Bearer <token>'
```

For zone transfer to secondaries and DNSSEC, see
[authoritative interop](authoritative-interop.md) and [DNSSEC](dnssec.md).
