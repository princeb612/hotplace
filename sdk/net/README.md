### network

```mermaid
mindmap
  root((net))
    network_server
      multiplexer
        multiplexer_epoll
        multiplexer_iocp
      network_protocol_group
        network_protocol
      network_session_manager
        network_session
      basic_socket
        server_socket
          tcp_server_socket
            tls_server_socket
          udp_server_socket
            dtls_server_socket
        client_socket
          tcp_client_socket
            tls_client_socket
          udp_client_socket
            dtls_client_socket
    http_server
      http_server_builder
      http_uri
      http_header
      network_protocol
        http_protocol
        http2_protocol
      http_request
      http_response
      http_router
        html_documents
        http_authentication_provider
          basic_authentication_provider
          digest_access_authentication_provider
          bearer_authentication_provider
        http_authentication_resolver
          basic_credentials
          digest_credentials
          bearer_credentials
          oauth2_credentials
          custom_credentials
        oauth2_provider
          oauth2_grant_provider
            oauth2_authorization_code_grant_provider
            oauth2_implicit_grant_provider
            oauth2_resource_owner_password_credentials_grant_provider
            oauth2_client_credentials_grant_provider
    ipaddr_acl
    tls_session
    tls_protection
    tls_record
      tls_record_ack
      tls_record_alert
      tls_record_application_data
      tls_record_change_cipher_spec
      tls_record_handshake
      tls_records
      tls_record_bilder
      dtls13_ciphertext
    tls_handshake
      tls_handshake_certificate
      tls_handshake_certificate_verify
      tls_handshake_client_hello
      tls_handshake_client_key_exchange
      tls_handshake_server_key_exchange
      tls_handshake_encrypted_extensions
      tls_handshake_end_of_early_data
      tls_handshake_finished
      tls_handshake_new_session_ticket
      tls_handshake_server_hello
      tls_handshakes
      tls_handshake_builder
    tls_extension
      tls_extension_alpn
      tls_extension_alps
      tls_extension_compress_certificate
      tls_extension_ec_point_formats
      tls_extension_encrypted_client_hello
      tls_extension_key_share
      tls_extension_pre_shared_key
      tls_extension_psk_key_exchange_modes
      tls_extension_quic_transport_parameters
      tls_extension_signature_algorithms
      tls_extension_sni
      tls_extension_status_request
      tls_extension_supported_groups
      tls_extension_supported_versions
      tls_extensions
      tls_extension_builder
    quic_packet
      quic_packet_0rtt
      quic_packet_1rtt
      quic_packet_handshake
      quic_packet_initial
      quic_packet_retry
      quic_packet_version_negotiation
      quic_packet_builder
    quic_frame
      quic_frame_ack
      quic_frame_connection_close
      quic_frame_crypto
      quic_frame_handshake_done
      quic_frame_new_token
      quic_frame_padding
      quic_frame_ping
      quic_frame_reset_stream
      quic_frame_stop_sending
      quic_frames
      quic_frame_builder
```

### references

* books
* RFC
  * TLS
    * RFC 2246 The TLS Protocol Version 1.0
    * RFC 4346 The Transport Layer Security (TLS) Protocol Version 1.1
    * RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2
    * RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
    * RFC 8448 Example Handshake Traces for TLS 1.3
  * DTLS
    * RFC 4347 Datagram Transport Layer Security
    * RFC 6347 Datagram Transport Layer Security Version 1.2
    * RFC 9147 The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
  * QUIC
    * RFC 9000 QUIC: A UDP-Based Multiplexed and Secure Transport
    * RFC 9001 Using TLS to Secure QUIC
  * HTTP
    * RFC 2068 Hypertext Transfer Protocol -- HTTP/1.1
    * RFC 7540 Hypertext Transfer Protocol Version 2 (HTTP/2)
    * RFC 7541 HPACK: Header Compression for HTTP/2
    * RFC 9113 HTTP/2
    * RFC 9114 HTTP/3
    * RFC 9204 QPACK: Field Compression for HTTP/3
* online resources
  * The SSLKEYLOGFILE Format for TLS
    * https://www.ietf.org/archive/id/draft-thomson-tls-keylogfile-00.html
