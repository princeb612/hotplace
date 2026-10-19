# TLS 1.3 handshake-flow sketch

This page is a compact message-order sketch for the 1-RTT and 0-RTT paths, not a complete state-machine specification.

## 1-RTT path

1. Client → Server: `ClientHello`
2. Server → Client: `ServerHello`, `EncryptedExtensions`, `Certificate`, `CertificateVerify`, `Finished`
3. Client → Server: `Finished`
4. Server → Client: `NewSessionTicket` (post-handshake, when issued)
5. Both directions: application data
6. Both directions: `close_notify` during orderly shutdown

## 0-RTT sketch

The client sends `ClientHello` with a `pre_shared_key` offer and early data; the server response shown here includes `ServerHello`, `EncryptedExtensions`, and `Finished`. The actual accepted/rejected early-data path and complete message ordering depend on negotiation and server policy, so this abbreviated diagram should not be used as a full trace template.

Related test material: [TLS test cases](README.md), [TLS 1.3 captures](tls13/README.md).
