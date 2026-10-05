# test certificates

The `etc/cert/` area contains certificate and private-key fixtures used by hotplace tests, together with scripts for generating and converting test certificate material. These files are repository-managed test resources; they are not a production certificate store.

## Directory map

```text
cert/
├─ trust/
│  └─ trust.crt              — trust certificate for Authenticode tests
│
├─ server-*.crt              — server certificate fixtures
├─ server-*.key              — corresponding server private-key fixtures
├─ issue.sh                  — generate self-signed certificate sets
├─ crt2der.sh                — CRT/PEM → DER conversion helper
└─ CMakeLists.txt            — distribute fixtures to build/test locations
```

## Certificate families

The certificate generation script supports the certificate families used by the test environment, including:

- RSA / RSA-PSS
- ECDSA (P-256, P-384, P-521)
- EdDSA (Ed25519, Ed448)
- ML-DSA (ML-DSA-44, ML-DSA-65, ML-DSA-87)
- SLH-DSA variants

The checked-in server fixtures cover the algorithms required by the current test tree. `issue.sh` is the source-side mechanism for regenerating self-signed test material when a new fixture set is needed.

## Resource distribution

`cert/CMakeLists.txt` copies the repository resources into the build tree used by tests:

```text
etc/cert/
   │
   ├─ trust/trust.crt
   │       └──────────────→ test/applet/authenticode/
   │
   ├─ server-*.crt / server-*.key
   │       ├──────────────→ test/testcase/quic/
   │       ├──────────────→ test/testcase/tls/
   │       ├──────────────→ test/applet/dtlsserver/
   │       ├──────────────→ test/applet/httpserver1/
   │       ├──────────────→ test/applet/httpserver2/
   │       └──────────────→ test/applet/tlsserver/
   │
   └─ server-*.der
           └──────────────→ test/testcase/asn.1/
```

This distribution step is important when reading the tests: the certificate files in those build/test directories are copies of the repository-managed fixtures rather than independent certificate sources.

## Generation

`issue.sh` accepts a certificate family/variant and creates a self-signed root/server test set. It also provides `clean` to remove generated certificate material.

Examples:

```text
./issue.sh ecdsa
./issue.sh rsa
./issue.sh rsapss
./issue.sh mldsa65
./issue.sh slhdsa128f
./issue.sh ed25519
./issue.sh clean
```

`crt2der.sh` converts a `.crt` certificate to DER when a binary certificate representation is required by a test.

## Related areas

- `test/applet/authenticode/` — trust certificate consumer
- `test/applet/dtlsserver/` — DTLS server certificate consumer
- `test/applet/httpserver1/` and `test/applet/httpserver2/` — HTTP server certificate consumers
- `test/applet/tlsserver/` — TLS server certificate consumer
- `test/testcase/tls/` — TLS certificate test fixtures
- `test/testcase/quic/` — QUIC certificate test fixtures
- `test/testcase/asn.1/` — DER certificate test data

## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1097
Documented with GPT-5.6 Luna
— source identity, implementation detail & relationships
```
