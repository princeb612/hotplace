## Publication

```text
hotplace source-tree documentation
Edition 2 · Revision 1105
Source basis: Revision 1105
Documented with GPT-6
Documentation scope: certificate fixtures, generation and distribution
```

# Test certificates

## 1. Role

`etc/cert/` contains certificate and private-key fixtures used by hotplace tests, together with scripts for generating and converting test certificate material. These files are repository-managed test resources, not a production certificate store or a trust-policy recommendation.

## 2. Model

```text
cert/
├─ trust/
│  └─ trust.crt
├─ server-*.crt
├─ server-*.key
├─ server-*.der
├─ issue.sh
├─ crt2der.sh
└─ CMakeLists.txt
```

The certificate generation script supports these families/variants:

- RSA and RSA-PSS
- ECDSA P-256, P-384 and P-521
- EdDSA Ed25519 and Ed448
- ML-DSA-44, ML-DSA-65 and ML-DSA-87
- SLH-DSA variants (128s/128f, 192s/192f, 256s/256f)

The default variant is ECDSA P-384 when `issue.sh` is run without an argument. The exact supported algorithm names are listed in [help.md](help.md) and in the script's accepted argument handling.

## 3. Important behavior and lifetime

### Fixture generation

`issue.sh` generates self-signed root/server test material with OpenSSL and creates the server certificate using the generated root. It configures test-oriented subject alternative names including `test.com`, `localhost`, and `127.0.0.1`. The script's `clean` option removes generated certificate artifacts in the current certificate directory; use it only when that cleanup is intended.

`crt2der.sh` converts a supplied `.crt` file to DER and prints the resulting certificate for inspection. It is a format-conversion helper, not a certificate-validation command.

### Build-time distribution

`cert/CMakeLists.txt` copies `trust/trust.crt` into the Authenticode applet's build-tree directory; copies `server-*.crt` and `server-*.key` into QUIC/TLS test and DTLS/HTTP/TLS server applet directories; and copies `server-*.der` into ASN.1 testcase locations.

This means a test that opens a certificate under its build directory is generally consuming a copy of a repository fixture. Updating a fixture should be done in `etc/cert/`, then verified against the CMake copy destinations.

## 4. Example from the source scripts

Generate a test certificate set by choosing a supported family/variant:

```sh
./issue.sh ecdsa
./issue.sh rsa
./issue.sh rsapss
./issue.sh mldsa65
./issue.sh slhdsa128f
./issue.sh ed25519
```

Convert a certificate to DER when a testcase requires binary certificate data:

```sh
./crt2der.sh server-ecdsa.crt
```

These commands describe script usage; they were not executed as part of this documentation update.

## 5. Relationships

- `test/applet/authenticode/` — trust certificate consumer.
- `test/applet/dtlsserver/` — DTLS server certificate consumer.
- `test/applet/httpserver1/` and `test/applet/httpserver2/` — HTTP server certificate consumers.
- `test/applet/tlsserver/` — TLS server certificate consumer.
- `test/testcase/tls/` and `test/testcase/quic/` — TLS/QUIC test fixtures.
- `test/testcase/asn.1/` — DER certificate test data.

## 6. References

- [Generation options](help.md)
- `issue.sh`
- `crt2der.sh`
- `CMakeLists.txt`
- [Repository resource map](../README.md)
