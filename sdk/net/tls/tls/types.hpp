/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TLS_TYPES__
#define __HOTPLACE_SDK_NET_TLS_TLS_TYPES__

#include <hotplace/sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

// record
class dtls13_ciphertext;
class tls_record;
class tls_record_ack;
class tls_record_alert;
class tls_record_application_data;
class tls_record_builder;
class tls_record_change_cipher_spec;
class tls_record_handshake;
class tls_record_unknown;
class tls_records;

// handshake
class dtls_handshake_fragmented;
class tls_handshake;
class tls_handshake_builder;
class tls_handshake_certificate;
class tls_handshake_certificate_verify;
class tls_handshake_client_hello;
class tls_handshake_client_key_exchange;
class tls_handshake_encrypted_extensions;
class tls_handshake_end_of_early_data;
class tls_handshake_finished;
class tls_handshake_hello_verify_request;
class tls_handshake_new_session_ticket;
class tls_handshake_server_hello;
class tls_handshake_server_hello_done;
class tls_handshake_server_key_exchange;
class tls_handshake_unknown;
class tls_handshakes;

// extension
class tls_extension;
class tls_extension_alpn;
class tls_extension_alps;
class tls_extension_builder;
class tls_extension_compress_certificate;
class tls_extension_early_data;
class tls_extension_ec_point_formats;
class tls_extension_encrypted_client_hello;
class tls_extension_key_share;
class tls_extension_pre_shared_key;
class tls_extension_psk_key_exchange_modes;
class tls_extension_quic_transport_parameters;
class tls_extension_renegotiation_info;
class tls_extension_signature_algorithms;
class tls_extension_sni;
class tls_extension_status_request;
class tls_extension_supported_groups;
class tls_extension_supported_versions;
class tls_extension_unknown;
class tls_extensions;

// tls_extension_key_share
class tls_extension_client_key_share;
class tls_extension_server_key_share;
// tls_extension_pre_shared_key
class tls_extension_client_psk;
class tls_extension_psk;
class tls_extension_server_psk;
// tls_extension_supported_versions
class tls_extension_client_supported_versions;
class tls_extension_server_supported_versions;

}  // namespace net
}  // namespace hotplace

#endif
