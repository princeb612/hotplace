/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET__
#define __HOTPLACE_SDK_NET__

/* top-most */
#include <sdk/base.hpp>
#include <sdk/crypto.hpp>
#include <sdk/io.hpp>
#include <sdk/net/types.hpp>

/* basic */
#include <sdk/net/basic/basic_socket.hpp>
#include <sdk/net/basic/client_socket.hpp>
#include <sdk/net/basic/server_socket.hpp>

/* basic/socket */
#include <sdk/net/basic/socket/tcp_client_socket.hpp>
#include <sdk/net/basic/socket/tcp_server_socket.hpp>
#include <sdk/net/basic/socket/udp_client_socket.hpp>
#include <sdk/net/basic/socket/udp_server_socket.hpp>
#include <sdk/net/basic/util/ipaddr_acl.hpp>

/* basic/tls */
#include <sdk/net/basic/tls/dtls_client_socket.hpp>
#include <sdk/net/basic/tls/dtls_server_socket.hpp>
#include <sdk/net/basic/tls/sdk.hpp>
#include <sdk/net/basic/tls/tls.hpp>
#include <sdk/net/basic/tls/tls_client_socket.hpp>
#include <sdk/net/basic/tls/tls_server_socket.hpp>
#include <sdk/net/basic/tls/tlscert.hpp>

/* http */
#include <sdk/net/http/html_documents.hpp>
#include <sdk/net/http/http_authentication_provider.hpp>
#include <sdk/net/http/http_authentication_resolver.hpp>
#include <sdk/net/http/http_client.hpp>
#include <sdk/net/http/http_header.hpp>
#include <sdk/net/http/http_protocol.hpp>
#include <sdk/net/http/http_request.hpp>
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/http/http_response.hpp>
#include <sdk/net/http/http_router.hpp>
#include <sdk/net/http/http_server.hpp>
#include <sdk/net/http/http_server_builder.hpp>
#include <sdk/net/http/http_uri.hpp>
#include <sdk/net/http/types.hpp>

/* http/auth */
#include <sdk/net/http/auth/basic_authentication_provider.hpp>
#include <sdk/net/http/auth/basic_credentials.hpp>
#include <sdk/net/http/auth/bearer_authentication_provider.hpp>
#include <sdk/net/http/auth/bearer_credentials.hpp>
#include <sdk/net/http/auth/custom_credentials.hpp>
#include <sdk/net/http/auth/digest_access_authentication_provider.hpp>
#include <sdk/net/http/auth/digest_credentials.hpp>
#include <sdk/net/http/auth/oauth2.hpp>
#include <sdk/net/http/auth/oauth2_credentials.hpp>
#include <sdk/net/http/auth/rfc2617_digest.hpp>

/* http/http2 */
#include <sdk/net/http/http2/hpack.hpp>
#include <sdk/net/http/http2/http2_frame.hpp>
#include <sdk/net/http/http2/http2_protocol.hpp>
#include <sdk/net/http/http2/http2_serverpush.hpp>
#include <sdk/net/http/http2/http2_session.hpp>
#include <sdk/net/http/http2/http_header_compression.hpp>

/* http/http3 */
#include <sdk/net/http/http3/qpack.hpp>

/* server */
#include <sdk/net/server/network_protocol.hpp>
#include <sdk/net/server/network_server.hpp>
#include <sdk/net/server/network_session.hpp>
#include <sdk/net/server/network_stream.hpp>

/* TLS */
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

/* tls/tls */
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls/types.hpp>

/* TLS record */
#include <sdk/net/tls/tls/record/dtls13_ciphertext.hpp>
#include <sdk/net/tls/tls/record/tls_record.hpp>
#include <sdk/net/tls/tls/record/tls_record_ack.hpp>
#include <sdk/net/tls/tls/record/tls_record_alert.hpp>
#include <sdk/net/tls/tls/record/tls_record_application_data.hpp>
#include <sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <sdk/net/tls/tls/record/tls_record_change_cipher_spec.hpp>
#include <sdk/net/tls/tls/record/tls_record_handshake.hpp>
#include <sdk/net/tls/tls/record/tls_record_unknown.hpp>
#include <sdk/net/tls/tls/record/tls_records.hpp>

/* TLS handshake */
#include <sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_builder.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_certificate.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_certificate_verify.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_client_hello.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_client_key_exchange.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_encrypted_extensions.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_end_of_early_data.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_finished.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_new_session_ticket.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_server_hello.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_server_key_exchange.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_unknown.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshakes.hpp>

/* TLS extension */
#include <sdk/net/tls/tls/extension/tls_extension.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_alpn.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_alps.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_builder.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_compress_certificate.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_ec_point_formats.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_encrypted_client_hello.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_key_share.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_pre_shared_key.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_psk_key_exchange_modes.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_quic_transport_parameters.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_signature_algorithms.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_sni.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_status_request.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_supported_groups.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_supported_versions.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_unknown.hpp>
#include <sdk/net/tls/tls/extension/tls_extensions.hpp>

/* QUIC */
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>
#include <sdk/net/tls/quic/types.hpp>

/* QUIC packet */
#include <sdk/net/tls/quic/packet/quic_packet.hpp>
#include <sdk/net/tls/quic/packet/quic_packet_builder.hpp>

/* QUIC frame */
#include <sdk/net/tls/quic/frame/quic_frame.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_builder.hpp>
#include <sdk/net/tls/quic/frame/quic_frames.hpp>

// TLS over TCP
#include <sdk/net/tls/basic/tls_client_socket.hpp>

#endif
