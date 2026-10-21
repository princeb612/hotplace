## Publication

```text
hotplace source-tree documentation
Edition 2 · Revision 1105
Source basis: Revision 1105
Documented with GPT-6
Documentation scope: certificate script arguments
```

# Test certificate generation options

This helper note documents the accepted arguments for `issue.sh`. Run the script from `etc/cert/`; generated files are written in the current directory.

| Argument | Generated test key/certificate family |
|---|---|
| `rsa` | RSA 3072 |
| `rsapss` | RSA-PSS 3072 |
| `ecdsa` | ECDSA P-384 (default) |
| `p-256` | ECDSA P-256 |
| `p-384` | ECDSA P-384 |
| `p-521` | ECDSA P-521 |
| `mldsa`, `mldsa65` | ML-DSA-65 |
| `mldsa44` | ML-DSA-44 |
| `mldsa87` | ML-DSA-87 |
| `slhdsa`, `slhdsa128f` | SLH-DSA-SHA2-128f |
| `slhdsa128s` | SLH-DSA-SHA2-128s |
| `slhdsa192f` / `slhdsa192s` | SLH-DSA-SHA2-192f / 192s |
| `slhdsa256f` / `slhdsa256s` | SLH-DSA-SHA2-256f / 256s |
| `eddsa`, `ed25519` | EdDSA Ed25519 |
| `ed448` | EdDSA Ed448 |
| `clean` | Remove generated `root-*`, `server-*`, `*.ext`, `*.pem`, and `*.srl` files |

The script normalizes arguments to lowercase. The generated material is for local tests only; do not use these self-signed keys/certificates as production credentials or trust anchors.
