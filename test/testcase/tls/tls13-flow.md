# Developer Notes - TLS 1.3 handshake-flow sketch

This page is a compact message-order aid for reading traces. It is not a complete TLS state machine, and optional messages vary with negotiation, resumption, authentication, and peer policy.

## 1-RTT full-handshake sketch

```text
Client                         Server
  | -------- ClientHello ------> |
  | <------- ServerHello ------- |
  | <--- EncryptedExtensions --- |
  | <------- Certificate ------- |  when certificate authentication is used
  | <---- CertificateVerify ---- |  when applicable
  | <--------- Finished -------- |
  | --------- Finished --------> |
  | <---- NewSessionTicket ----- |  optional post-handshake
  | <====== Application Data ===>|
  | <====== close_notify ======> |  orderly shutdown, direction may vary
```

A compatibility `ChangeCipherSpec` can appear in TLS 1.3 captures but is not a TLS 1.3 handshake state transition equivalent to the TLS 1.2 change of record protection. The figure omits record-layer details and encrypted handshake payload boundaries.

## 0-RTT sketch

A resuming client may send a `ClientHello` with a `pre_shared_key` offer and early application data. The server's acceptance or rejection of early data changes the subsequent exchange; therefore a single abbreviated message list is not a complete 0-RTT trace template. Early data also has replay-related semantics that are outside the scope of this sketch.

## Where the repository demonstrates these paths

- [Top-level TLS testcase README](README.md) — executable test inventory and YAML record replay.
- [TLS 1.3 capture README](tls13/README.md) — selected suite and key-exchange captures, plus a handshake-failure capture.
- `testcase_rfc8448_*.cpp` — fixed examples from RFC 8448, including the HelloRetryRequest example in `testcase_rfc8448_5.cpp`.
- `testcase_helloretryrequest.cpp` — separate HelloRetryRequest-oriented testcase.

Do not infer that every message shown here has an independent assertion in every listed source file; consult the testcase implementation and current report for the exact claim.
