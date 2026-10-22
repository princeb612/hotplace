## Publication

```text
hotplace source-tree documentation
Edition 2 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
Documentation scope: certificate fixtures, generation and distribution
```

# Test certificates

## 1. Role

`etc/cert/` contains certificate and private-key fixtures used by hotplace tests, together with scripts for generating test material and converting certificates to DER. These files are repository-managed test resources, not a production certificate store or a trust-policy recommendation.

Keep the two certificate roles distinct:

- `trust/trust.crt` is the trust bundle copied for the Authenticode applet.
- `root-*` and `server-*` files created by `issue.sh` are generated test material. The script does not automatically replace `trust/trust.crt`.

## 2. Model

```text
cert/
├─ trust/
│  └─ trust.crt
├─ server-*.crt / server-*.key
├─ server-*.der             (when generated/provided)
├─ issue.sh
├─ crt2der.sh
├─ help.md
└─ CMakeLists.txt
```

The `issue.sh` script accepts these algorithm families/variants:

- RSA 3072 and RSA-PSS 3072
- ECDSA P-256, P-384 and P-521 (default: P-384)
- EdDSA Ed25519 and Ed448
- ML-DSA-44, ML-DSA-65 and ML-DSA-87
- SLH-DSA-SHA2 variants 128s/128f, 192s/192f and 256s/256f

The accepted argument spellings and the `clean` option are listed in [help.md](help.md).

## 3. Important behavior and lifetime

### Fixture generation

`issue.sh` generates a root key and self-signed root certificate, then generates a server key and a server certificate signed by that generated root. The server certificate includes test-oriented subject alternative names `test.com`, `localhost` and `127.0.0.1`. The script also creates an encrypted server-key intermediate and writes an unencrypted `server-<type>.key` for test use.

The generated root certificate is not the same thing as the repository's `trust/trust.crt` bundle. Regenerating server fixtures does not, by itself, update the bundle copied to the Authenticode applet.

The `clean` argument removes matching generated files in the current directory, including `root-*`, `server-*`, `*.ext`, `*.pem` and `*.srl`. Run it only when that cleanup is intended.

### DER conversion

`crt2der.sh` accepts a `.crt` input, writes a corresponding `.der` file, and prints the DER certificate for inspection. It is a format-conversion helper, not a certificate-validation command. Run it from the certificate directory or provide an input path whose resulting output location is understood.

### Build-time distribution

`etc/cert/CMakeLists.txt` copies:

- `trust/trust.crt` to `test/applet/authenticode/` in the build tree.
- `server-*.crt` and `server-*.key` to `test/testcase/quic/`, `test/testcase/tls/`, and the `dtlsserver`, `httpserver1`, `httpserver2`, and `tlsserver` applet build directories.
- Any `server-*.der` matches to `test/testcase/asn.1/` in the build tree.

The DER copy rule is present even though the current tracked `etc/cert/` listing does not show a `server-*.der` file. If ASN.1 tests require those fixtures, create/obtain the intended DER files and verify the CMake configure/build behavior rather than assuming the files are already tracked.

A test that opens a certificate under its build directory is generally consuming a copy of a repository fixture. Update the source fixture under `etc/cert/`, then verify the copy destinations and the consumers that depend on it.

## 4. Example from the source scripts

From `etc/cert/`, generate a selected family:

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

These commands describe the scripts' interfaces; they were not executed as part of this documentation update.

## 5. Relationships

- `test/applet/authenticode/` — consumer of the trust bundle.
- `test/applet/dtlsserver/` — DTLS server certificate/key consumer.
- `test/applet/httpserver1/` and `test/applet/httpserver2/` — HTTP server certificate/key consumers.
- `test/applet/tlsserver/` — TLS server certificate/key consumer.
- `test/testcase/tls/` and `test/testcase/quic/` — TLS/QUIC test fixtures.
- `test/testcase/asn.1/` — intended consumer of DER certificate test data.

## 6. References

- [Generation options](help.md)
- `issue.sh`
- `crt2der.sh`
- `CMakeLists.txt`
- [Repository resource map](../README.md)
