# test/testcase

## Publication

```text
hotplace source-tree documentation
Edition 2 · Revision 1105
Source basis: Revision 1105
Documented with GPT-6
— testcase organization, execution & verification
```

`test/testcase` is the automated verification layer for the SDK. Test groups are organized primarily by the feature/protocol boundary they verify, and each group is built as a `test-<module>` executable.

## Test groups

| Group | Role |
|---|---|
| `base` | common containers, utilities, strings, system facilities and unittest infrastructure |
| `encode` | encoding/decoding facilities |
| `io` | I/O and parser/system functionality |
| `cbor` | CBOR encoding/decoding and RFC examples |
| `asn.1` | ASN.1 parsing, construction, encoding/decoding and constraints |
| `crypto` | cryptographic primitives, keys, KDF, signatures, PQC and related backends |
| `jose` | JOSE/JWK/JWS/JWE behavior and RFC examples |
| `cose` | COSE/CBOR cryptographic processing and RFC examples |
| `net` | network/basic HTTP support and protocol components |
| `tls` | TLS/DTLS behavior and packet/handshake test material |
| `quic` | QUIC packet/session/HTTP3-related verification |
| `odbc` | ODBC integration |
| `linux` | Linux-specific behavior |
| `windows` | Windows-specific behavior |

The exact source/testcase layout can evolve independently of the SDK source tree; the stable meaning is the verification boundary represented by each group.

## Practical usage patterns found in testcases

The testcase tree also records how SDK APIs are composed in real code. These examples are useful entry points when documenting a component's Behavior Model; they are representative usage paths, not a claim that every possible input or failure mode is covered.

| Usage pattern | Representative source | What the code demonstrates |
|---|---|---|
| Configure and route diagnostics | [Applet logger setup](../applet/tcpserver1/sample.cpp); [ASN.1 diagnostic output](asn.1/sample.cpp) | `logger_builder` setup, callback-based output, and formatted token diagnostics |
| Encode/decode with incremental input | [Base16 testcase](encode/testcase_base16.cpp) | One-shot round trip compared with `encoder_stream` / `decoder_stream` processing across chunk boundaries |
| Collect typed arguments for formatting | [valist vectors](base/basic/testvector_valist.cpp); [ASN.1 notation/DER output](asn.1/testcase_basic1.cpp) | Build a `valist` from typed values and render them through a format string |
| Search generic sequences | [KMP testcase](base/pattern/testcase_kmp.cpp) | Learn a pattern, search byte/object/pointer sequences, and supply a custom comparator |
| Load and publish semantic modules | [ASN.1 loader testcase](asn.1/loader/testcase_loader.cpp) | Keep file parsing, semantic publishing, registry lookup, and module resolution as separate steps |
| Parse and compare protocol representations | [CBOR vectors](cbor/testvector_cbor.cpp); [ASN.1 DER vectors](asn.1/testvector_der.cpp) | Compare encoded bytes with decoded/diagnostic representations and inspect output through the logger |

When adding a practical example to an SDK document, prefer the smallest source-backed sequence that reveals the API relationship. Keep expected-value assertions and meaningful lifetime/error-handling notes, and link the original testcase under Relationships rather than copying an entire test function.

### Additional source-backed paths worth following

| Area | Representative source | Practical sequence exposed |
|---|---|---|
| Command-line parsing | [base/basic/testcase_cmdline.cpp](base/basic/testcase_cmdline.cpp) | Register required/optional tokens, dispatch callbacks into an application option object, and reject missing required input |
| ASN.1 semantic loading | [asn.1/loader/testcase_loader.cpp](asn.1/loader/testcase_loader.cpp) | Load source into a parse tree, publish semantic modules, resolve a module/type through the registry |
| Symmetric cipher | [crypto/crypt/testcase_cipher_encrypt.cpp](crypto/crypt/testcase_cipher_encrypt.cpp) | Build an algorithm/mode-specific wrapper, encrypt, decrypt, and release the operation object |
| Authenticated encryption | [crypto/crypt/testcase_crypto_aead.cpp](crypto/crypt/testcase_crypto_aead.cpp) | Keep key, IV/nonce, AAD, ciphertext, and authentication tag as distinct values across encrypt/decrypt |
| Key agreement | [crypto/key/testcase_keyexchange.cpp](crypto/key/testcase_keyexchange.cpp) | Generate two local key pairs, exchange public shares, derive secrets independently, compare the result |
| JWE processing | [jose/testcase_rfc7516.cpp](jose/testcase_rfc7516.cpp) | Load key material, open a JOSE context, decrypt a serialized JWE, inspect the result, close the context |
| COSE processing | [cose/testcase_cose.cpp](cose/testcase_cose.cpp) | Compose a signed/encrypted CBOR message and pass the encoded message through processing/verification |
| Network ACL | [net/basic/testcase_acl.cpp](net/basic/testcase_acl.cpp) | Add exact/prefix/range rules, switch whitelist/blacklist defaults, and check peer-address decisions |

These paths extend the initial examples across argument handling, ASN.1, symmetric and authenticated encryption, key agreement, JOSE/COSE, and network admission. They are navigation aids for source-backed examples, not a test-coverage summary or a claim that this documentation pass executed the cases.

## Build and CTest flow

`test/testcase/CMakeLists.txt` adds the testcase groups and copies `test.sh` into the build tree. At the project level, the root `maketest()` helper creates each `test-<module>` executable and registers it with CTest when that target is configured for CTest.

```text
CMake configure/build
        │
        ▼
 test/testcase/CMakeLists.txt
        │
        ├── base / encode
        ├── io / cbor / asn.1
        ├── crypto / jose / cose
        ├── net / tls / quic
        ├── odbc (when SUPPORT_ODBC)
        └── linux or windows
                 │
                 ▼
          test-<module>
                 │
                 └── CTest registration
```

CTest is the normal automated test entry point in the MinGW64/GCC, Windows/MSVC, CentOS 7 (gcc 4.8.5), and Rocky 8 environments. Ubuntu 20 uses CTest together with Sanitizer; CentOS 7 and Rocky 8 use `test.sh` as an optional additional Valgrind pass.

## Latest recorded test snapshot

The latest report summary is retained in [Test Report Snapshot](test-report-status.md). It must be read separately from this README's source/documentation basis:

- Report package: `ttestcase-reports-revision1105-working.zip.zip` (uploaded 2026-10-18; report snapshot received 2026-10-17).
- Last-run context supplied in the conversation: **Revision 1104 · MinGW64/GCC · CTest**.
- Provenance limit: the report files do not independently identify a source commit/revision, exact GCC version, build flags, or full CTest command line.
- Result summary: 29,103 pass, 336 expt, 0 fail, 93 skip, 5 triv categorized entries; the ODBC report has no categorized rows and is excluded from that total.
- Maintenance rule: keep this last known result visible until a newer report snapshot supersedes it. A newer source/documentation revision is not itself a new test run.

## Environment-specific verification

The repository uses CTest as the normal testcase execution baseline. Additional diagnostic tools depend on the target environment:

| Environment | Primary execution | Additional verification |
|---|---|---|
| MinGW64 / GCC | `ctest` | Application Verifier |
| Ubuntu 20 | `ctest` | Sanitizer |
| CentOS 7 (gcc 4.8.5) | `ctest` | `test.sh` → Valgrind: `memcheck`, `helgrind`, `drd` |
| Rocky 8 | `ctest` | `test.sh` → Valgrind: `memcheck`, `helgrind`, `drd` |
| Windows / MSVC | `ctest` | Application Verifier |

`test.sh` is therefore an additional Valgrind verification path on CentOS 7 and Rocky 8, not the primary testcase execution mechanism. A testcase being registered with CTest does not imply that every environment runs it through the same diagnostic tool.

## Running `test.sh`

From the built `test/testcase` directory:

```bash
./test.sh
```

runs the groups selected by the script. A single group can be selected:

```bash
./test.sh base
./test.sh crypto
./test.sh tls
```

The current default script selection is:

```text
base encode
  io cbor asn.1
  crypto cose jose
  net tls quic
  windows   # on Cygwin/MSYS
  linux     # otherwise
```

ODBC is present in the CMake testcase graph when `SUPPORT_ODBC` is enabled, but it is **not included in the current no-argument `test.sh` array**. That distinction should be preserved when interpreting test coverage.

## Valgrind diagnostic pass

When Valgrind is available, `test.sh` runs each selected executable through:

- `memcheck` — memory/leak/origin checking
- `helgrind` — thread synchronization checking
- `drd` — thread error checking

The reports are written as `report-memcheck`, `report-helgrind`, and `report-drd` in the corresponding build directory. This pass is the CentOS 7 / Rocky 8 Valgrind verification path; it is not the general CTest mechanism.

Some runnable network applets are intentionally excluded from the automatic `test.sh` pass because they require user interaction or external peers. Those belong under `test/applet`.

## Test material and references

The testcase tree also preserves protocol-specific evidence and study material: RFC vectors, packet captures, TLS flow notes, cryptographic test vectors, schemas, and platform-specific investigation notes. These documents are part of the test history and should not be reduced to generic test descriptions.

## Related areas

- [`test`](../README.md) — overall test-area structure
- [`applet`](../applet/README.md) — runnable integration/example programs
- [`tool`](../tool/README.md) — test-supporting tools
- `sdk/base`, `sdk/io`, `sdk/crypto`, `sdk/net`, `sdk/odbc` — implementation areas verified here
