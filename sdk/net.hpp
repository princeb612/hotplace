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
#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/crypto.hpp>
#include <hotplace/sdk/io.hpp>
#include <hotplace/sdk/net/types.hpp>

/* basic */
#include <hotplace/sdk/net/basic/basic_socket.hpp>
#include <hotplace/sdk/net/basic/client_socket.hpp>
#include <hotplace/sdk/net/basic/server_socket.hpp>
#include <hotplace/sdk/net/basic/server_socket_adapter.hpp>
#include <hotplace/sdk/net/basic/server_socket_builder.hpp>
#include <hotplace/sdk/net/basic/types.hpp>

/* basic/naive */
#include <hotplace/sdk/net/basic/naive/naive_tcp_client_socket.hpp>
#include <hotplace/sdk/net/basic/naive/naive_tcp_server_socket.hpp>
#include <hotplace/sdk/net/basic/naive/naive_udp_client_socket.hpp>
#include <hotplace/sdk/net/basic/naive/naive_udp_server_socket.hpp>

/* basic/openssl */
#include <hotplace/sdk/net/basic/openssl/openssl_dtls_client_socket.hpp>
#include <hotplace/sdk/net/basic/openssl/openssl_dtls_server_socket.hpp>
#include <hotplace/sdk/net/basic/openssl/openssl_server_socket_adapter.hpp>
#include <hotplace/sdk/net/basic/openssl/openssl_tls.hpp>
#include <hotplace/sdk/net/basic/openssl/openssl_tls_client_socket.hpp>
#include <hotplace/sdk/net/basic/openssl/openssl_tls_context.hpp>
#include <hotplace/sdk/net/basic/openssl/openssl_tls_server_socket.hpp>
#include <hotplace/sdk/net/basic/openssl/sdk.hpp>
#include <hotplace/sdk/net/basic/openssl/types.hpp>

/* basic/trial */
#include <hotplace/sdk/net/basic/trial/client_socket_prosumer.hpp>
#include <hotplace/sdk/net/basic/trial/secure_client_socket.hpp>
#include <hotplace/sdk/net/basic/trial/secure_prosumer.hpp>
#include <hotplace/sdk/net/basic/trial/tls_composer.hpp>
#include <hotplace/sdk/net/basic/trial/trial_dtls_client_socket.hpp>
#include <hotplace/sdk/net/basic/trial/trial_dtls_server_socket.hpp>
#include <hotplace/sdk/net/basic/trial/trial_server_socket_adapter.hpp>
#include <hotplace/sdk/net/basic/trial/trial_tcp_client_socket.hpp>
#include <hotplace/sdk/net/basic/trial/trial_tls_client_socket.hpp>
#include <hotplace/sdk/net/basic/trial/trial_tls_server_socket.hpp>
#include <hotplace/sdk/net/basic/trial/trial_udp_client_socket.hpp>
#include <hotplace/sdk/net/basic/trial/types.hpp>

// basic/util
#include <hotplace/sdk/net/basic/util/ipaddr_acl.hpp>

/* http */
#include <hotplace/sdk/net/http/html_documents.hpp>
#include <hotplace/sdk/net/http/http_authentication_provider.hpp>
#include <hotplace/sdk/net/http/http_authentication_resolver.hpp>
#include <hotplace/sdk/net/http/http_client.hpp>
#include <hotplace/sdk/net/http/http_header.hpp>
#include <hotplace/sdk/net/http/http_protocol.hpp>
#include <hotplace/sdk/net/http/http_request.hpp>
#include <hotplace/sdk/net/http/http_resource.hpp>
#include <hotplace/sdk/net/http/http_response.hpp>
#include <hotplace/sdk/net/http/http_router.hpp>
#include <hotplace/sdk/net/http/http_server.hpp>
#include <hotplace/sdk/net/http/http_server_builder.hpp>
#include <hotplace/sdk/net/http/http_uri.hpp>
#include <hotplace/sdk/net/http/types.hpp>

/* http/auth */
#include <hotplace/sdk/net/http/auth/basic_authentication_provider.hpp>
#include <hotplace/sdk/net/http/auth/basic_credentials.hpp>
#include <hotplace/sdk/net/http/auth/bearer_authentication_provider.hpp>
#include <hotplace/sdk/net/http/auth/bearer_credentials.hpp>
#include <hotplace/sdk/net/http/auth/custom_credentials.hpp>
#include <hotplace/sdk/net/http/auth/digest_access_authentication_provider.hpp>
#include <hotplace/sdk/net/http/auth/digest_credentials.hpp>
#include <hotplace/sdk/net/http/auth/oauth2.hpp>
#include <hotplace/sdk/net/http/auth/oauth2_credentials.hpp>
#include <hotplace/sdk/net/http/auth/rfc2617_digest.hpp>

/* http/compression */
#include <hotplace/sdk/net/http/compression/http_dynamic_table.hpp>
#include <hotplace/sdk/net/http/compression/http_header_compression.hpp>
#include <hotplace/sdk/net/http/compression/http_header_compression_stream.hpp>
#include <hotplace/sdk/net/http/compression/http_huffman_codes.hpp>
#include <hotplace/sdk/net/http/compression/http_huffman_coding.hpp>
#include <hotplace/sdk/net/http/compression/http_static_table.hpp>
#include <hotplace/sdk/net/http/compression/types.hpp>

/* http/http2 */
#include <hotplace/sdk/net/http/http2/http2_frame.hpp>
#include <hotplace/sdk/net/http/http2/http2_frame_alt_svc.hpp>
#include <hotplace/sdk/net/http/http2/http2_frame_builder.hpp>
#include <hotplace/sdk/net/http/http2/http2_frame_continuation.hpp>
#include <hotplace/sdk/net/http/http2/http2_frame_data.hpp>
#include <hotplace/sdk/net/http/http2/http2_frame_goaway.hpp>
#include <hotplace/sdk/net/http/http2/http2_frame_headers.hpp>
#include <hotplace/sdk/net/http/http2/http2_frame_ping.hpp>
#include <hotplace/sdk/net/http/http2/http2_frame_priority.hpp>
#include <hotplace/sdk/net/http/http2/http2_frame_push_promise.hpp>
#include <hotplace/sdk/net/http/http2/http2_frame_rst_stream.hpp>
#include <hotplace/sdk/net/http/http2/http2_frame_settings.hpp>
#include <hotplace/sdk/net/http/http2/http2_frame_window_update.hpp>
#include <hotplace/sdk/net/http/http2/http2_protocol.hpp>
#include <hotplace/sdk/net/http/http2/http2_serverpush.hpp>
#include <hotplace/sdk/net/http/http2/http2_session.hpp>
#include <hotplace/sdk/net/http/http2/types.hpp>

/* http/http3 */
#include <hotplace/sdk/net/http/http3/http3_frame.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_builder.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_cancel_push.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_data.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_goaway.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_headers.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_max_push_id.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_metadata.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_origin.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_priority_update.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_push_promise.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_settings.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_unknown.hpp>
#include <hotplace/sdk/net/http/http3/http3_frames.hpp>
#include <hotplace/sdk/net/http/http3/types.hpp>

/* http/hpack */
#include <hotplace/sdk/net/http/hpack/hpack_dynamic_table.hpp>
#include <hotplace/sdk/net/http/hpack/hpack_encoder.hpp>
#include <hotplace/sdk/net/http/hpack/hpack_static_table.hpp>

/* http/qpack */
#include <hotplace/sdk/net/http/qpack/qpack_dynamic_table.hpp>
#include <hotplace/sdk/net/http/qpack/qpack_encoder.hpp>
#include <hotplace/sdk/net/http/qpack/qpack_static_table.hpp>

/* server */
#include <hotplace/sdk/net/server/network_protocol.hpp>
#include <hotplace/sdk/net/server/network_server.hpp>
#include <hotplace/sdk/net/server/network_session.hpp>
#include <hotplace/sdk/net/server/network_stream.hpp>
#include <hotplace/sdk/net/server/types.hpp>

/* tls */
#include <hotplace/sdk/net/tls/dtls_record_arrange.hpp>
#include <hotplace/sdk/net/tls/dtls_record_publisher.hpp>
#include <hotplace/sdk/net/tls/quic_packet_publisher.hpp>
#include <hotplace/sdk/net/tls/quic_session.hpp>
#include <hotplace/sdk/net/tls/sdk.hpp>
#include <hotplace/sdk/net/tls/sslkeylog_exporter.hpp>
#include <hotplace/sdk/net/tls/sslkeylog_importer.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_container.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>
#include <hotplace/sdk/net/tls/types.hpp>

/* tls/quic */
#include <hotplace/sdk/net/tls/quic/quic.hpp>
#include <hotplace/sdk/net/tls/quic/quic_encoded.hpp>
#include <hotplace/sdk/net/tls/quic/types.hpp>

/* tls/quic/packet */
#include <hotplace/sdk/net/tls/quic/packet/quic_packet.hpp>
#include <hotplace/sdk/net/tls/quic/packet/quic_packet_0rtt.hpp>
#include <hotplace/sdk/net/tls/quic/packet/quic_packet_1rtt.hpp>
#include <hotplace/sdk/net/tls/quic/packet/quic_packet_builder.hpp>
#include <hotplace/sdk/net/tls/quic/packet/quic_packet_handshake.hpp>
#include <hotplace/sdk/net/tls/quic/packet/quic_packet_initial.hpp>
#include <hotplace/sdk/net/tls/quic/packet/quic_packet_retry.hpp>
#include <hotplace/sdk/net/tls/quic/packet/quic_packet_version_negotiation.hpp>
#include <hotplace/sdk/net/tls/quic/packet/quic_packets.hpp>

/* tls/quic/frame */
#include <hotplace/sdk/net/tls/quic/frame/quic_frame.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame_ack.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame_builder.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame_connection_close.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame_crypto.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame_handshake_done.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame_new_connection_id.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame_new_token.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame_padding.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame_ping.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame_reset_stream.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame_stop_sending.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frame_stream.hpp>
#include <hotplace/sdk/net/tls/quic/frame/quic_frames.hpp>

/* tls/tls */
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls/types.hpp>

/* tls/tls/record */
#include <hotplace/sdk/net/tls/tls/record/dtls13_ciphertext.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_ack.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_alert.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_application_data.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_change_cipher_spec.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_handshake.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_unknown.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_records.hpp>

/* tls/tls/handshake */
#include <hotplace/sdk/net/tls/tls/handshake/dtls_handshake_fragmented.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_builder.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_certificate.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_certificate_verify.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_client_hello.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_client_key_exchange.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_encrypted_extensions.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_end_of_early_data.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_finished.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_hello_verify_request.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_new_session_ticket.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_server_hello.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_server_hello_done.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_server_key_exchange.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_unknown.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshakes.hpp>

/* tls/tls/extension */
#include <hotplace/sdk/net/tls/tls/extension/tls_extension.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_alpn.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_alps.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_builder.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_compress_certificate.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_early_data.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_ec_point_formats.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_encrypted_client_hello.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_key_share.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_pre_shared_key.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_psk_key_exchange_modes.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_quic_transport_parameters.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_renegotiation_info.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_signature_algorithms.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_sni.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_status_request.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_supported_groups.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_supported_versions.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_unknown.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extensions.hpp>

#endif
