## Publication

```text
hotplace source-tree documentation
Edition 2 · Revision 1108
Source basis: Revision 1105
Documented with GPT-6
Documentation scope: certificate fixtures, generation and distribution
```

# Test certificates

## 1. Role

`etc/cert/` stores certificate and private-key fixtures used by hotplace tests, together with scripts for generating test material and converting certificates to DER. These are repository-managed test resources, not a production certificate store or a trust-policy recommendation.

The files serve two distinct purposes:

- `trust/trust.crt` is the trust bundle copied for the Authenticode applet.
- `root-*` and `server-*` files produced by `issue.sh` are generated test material. The script does not automatically replace `trust/trust.crt`.

## 2. Data Model

```text
cert/
├─ trust/
│  └─ trust.crt
├─ server-*.crt / server-*.key
├─ server-*.der                 (when generated/provided)
├─ issue.sh
├─ crt2der.sh
├─ help.md
└─ CMakeLists.txt
```

The `issue.sh` script accepts these algorithm families and variants:

- RSA 3072 and RSA-PSS 3072
- ECDSA P-256, P-384 and P-521 (default: P-384)
- EdDSA Ed25519 and Ed448
- ML-DSA-44, ML-DSA-65 and ML-DSA-87
- SLH-DSA-SHA2 variants 128s/128f, 192s/192f and 256s/256f

Accepted argument spellings and the `clean` option are documented in [help.md](help.md).

The fixture set may contain certificates, private keys, intermediate PEM files, extension configuration files, serial files, and DER-encoded certificate files. Which files are present depends on generated/provided inputs; a CMake glob for a file pattern does not guarantee a matching tracked file exists.

## 3. Behavior Model

### Fixture generation

`issue.sh` generates a root key and self-signed root certificate, then generates a server key and a server certificate signed by that generated root. The server certificate includes test-oriented subject alternative names `test.com`, `localhost` and `127.0.0.1`. The script also creates an encrypted server-key intermediate and writes an unencrypted `server-<type>.key` for test use.

The generated root certificate is not the same thing as the repository's `trust/trust.crt` bundle. Regenerating server fixtures does not, by itself, update the trust bundle copied to the Authenticode applet.

The `clean` argument removes matching generated files in the current directory, including `root-*`, `server-*`, `*.ext`, `*.pem` and `*.srl`. Use it only when that cleanup is intended.

### DER conversion

`crt2der.sh` accepts a `.crt` input, writes a corresponding `.der` file, and prints the DER certificate for inspection. It is a format-conversion helper, not a certificate-validation command. Run it from the certificate directory or provide an input path whose output location is understood.

### Build-time distribution

`etc/cert/CMakeLists.txt` copies:

- `trust/trust.crt` to `test/applet/authenticode/` in the build tree.
- Matching `server-*.crt` and `server-*.key` files to `test/testcase/quic/`, `test/testcase/tls/`, and the `dtlsserver`, `httpserver1`, `httpserver2`, and `tlsserver` applet build directories.
- Matching `server-*.der` files to `test/testcase/asn.1/` in the build tree.

The DER copy rule exists even though the current tracked `etc/cert/` listing does not show a `server-*.der` file. If ASN.1 tests require those fixtures, create or obtain the intended DER files and verify the CMake configure/build behavior rather than assuming they are already tracked.

```text
issue.sh ──► root/server fixture files
crt2der.sh ──► DER certificate
                    │
                    ▼
              CMake file-copy rules
                    │
                    ▼
              build-tree consumers
```

A test that opens a certificate under its build directory generally consumes a copy of a repository fixture. Update the source fixture under `etc/cert/`, then check the copy destinations and the consumers that depend on it.

## 4. Relationships

- `test/applet/authenticode/` — consumer of the trust bundle.
- `test/applet/dtlsserver/` — DTLS server certificate/key consumer.
- `test/applet/httpserver1/` and `test/applet/httpserver2/` — HTTP server certificate/key consumers.
- `test/applet/tlsserver/` — TLS server certificate/key consumer.
- `test/testcase/tls/` and `test/testcase/quic/` — TLS/QUIC test fixtures.
- `test/testcase/asn.1/` — intended consumer of DER certificate test data.
- [Repository resource map](../README.md) — placement of certificate fixtures among other repository-managed resources.
