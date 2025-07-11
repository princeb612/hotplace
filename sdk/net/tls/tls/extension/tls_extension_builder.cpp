/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *          RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
 *          RFC 6066 Transport Layer Security (TLS) Extensions: Extension Definitions
 *          RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls/tls/extension/tls_extension.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_alpn.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_alps.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_builder.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_compress_certificate.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_early_data.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_ec_point_formats.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_encrypted_client_hello.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_key_share.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_pre_shared_key.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_psk_key_exchange_modes.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_quic_transport_parameters.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_renegotiation_info.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_signature_algorithms.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_sni.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_status_request.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_supported_groups.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_supported_versions.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_unknown.hpp>
#include <sdk/net/tls/tls/tls.hpp>

namespace hotplace {
namespace net {

tls_extension_builder::tls_extension_builder() : _hs(nullptr), _type(-1), _dir(from_any) {}

tls_extension_builder& tls_extension_builder::set(tls_handshake* hs) {
    _hs = hs;
    return *this;
}

tls_extension_builder& tls_extension_builder::set(uint16 type) {
    _type = type;
    return *this;
}

tls_extension_builder& tls_extension_builder::set(tls_direction_t dir) {
    _dir = dir;
    return *this;
}

tls_handshake* tls_extension_builder::get_handshake() { return _hs; }

uint16 tls_extension_builder::get_type() { return _type; }

tls_direction_t tls_extension_builder::get_direction() { return _dir; }

tls_extension* tls_extension_builder::build() {
    tls_extension* extension = nullptr;
    __try2 {
        auto handshake = get_handshake();
        if (nullptr == handshake) {
            __leave2;
        }
        switch (get_type()) {
            case tls_ext_server_name: /* 0x0000 */ {
                __try_new_catch_only(extension, new tls_extension_sni(handshake));
            } break;
            case tls_ext_status_request: /* 0x0005 */ {
                __try_new_catch_only(extension, new tls_extension_status_request(handshake));
            } break;
            case tls_ext_supported_groups: /* 0x000a */ {
                __try_new_catch_only(extension, new tls_extension_supported_groups(handshake));
            } break;
            case tls_ext_ec_point_formats: /* 0x000b */ {
                __try_new_catch_only(extension, new tls_extension_ec_point_formats(handshake));
            } break;
            case tls_ext_signature_algorithms: /* 0x000d */ {
                __try_new_catch_only(extension, new tls_extension_signature_algorithms(handshake));
            } break;
            case tls_ext_application_layer_protocol_negotiation: /* 0x0010 */ {
                __try_new_catch_only(extension, new tls_extension_alpn(handshake));
            } break;
            case tls_ext_compress_certificate: /* 0x001b */ {
                __try_new_catch_only(extension, new tls_extension_compress_certificate(handshake));
            } break;
            case tls_ext_pre_shared_key: /* 0x0029 */ {
                auto dir = get_direction();
                if (from_client == dir) {
                    __try_new_catch_only(extension, new tls_extension_client_psk(handshake));
                } else if (from_server == dir) {
                    __try_new_catch_only(extension, new tls_extension_server_psk(handshake));
                }
            } break;
            case tls_ext_supported_versions: /* 0x002b */ {
                auto dir = get_direction();
                if (from_client == dir) {
                    __try_new_catch_only(extension, new tls_extension_client_supported_versions(handshake));
                } else if (from_server == dir) {
                    __try_new_catch_only(extension, new tls_extension_server_supported_versions(handshake));
                }
            } break;
            case tls_ext_psk_key_exchange_modes: /* 0x002d */ {
                __try_new_catch_only(extension, new tls_extension_psk_key_exchange_modes(handshake));
            } break;
            case tls_ext_key_share: /* 0x0033 */ {
                auto dir = get_direction();
                if (from_client == dir) {
                    __try_new_catch_only(extension, new tls_extension_client_key_share(handshake));
                } else if (from_server == dir) {
                    __try_new_catch_only(extension, new tls_extension_server_key_share(handshake));
                }
            } break;
            case tls_ext_quic_transport_parameters: /* 0x0039 */ {
                __try_new_catch_only(extension, new tls_extension_quic_transport_parameters(handshake));
            } break;
            case tls_ext_application_layer_protocol_settings: /* 0x4469 */ {
                __try_new_catch_only(extension, new tls_extension_alps(handshake));
            } break;
            case tls_ext_encrypted_client_hello: /* 0xfe0d */ {
                __try_new_catch_only(extension, new tls_extension_encrypted_client_hello(handshake));
            } break;
            case tls_ext_renegotiation_info: /* 0xff01 */ {
                __try_new_catch_only(extension, new tls_extension_renegotiation_info(handshake));
            } break;
            case tls_ext_early_data: /* 0x002a */ {
                __try_new_catch_only(extension, new tls_extension_early_data(handshake));
            } break;

            case tls_ext_max_fragment_length:          /* 0x0001 */
            case tls_ext_client_certificate_url:       /* 0x0002 */
            case tls_ext_use_srtp:                     /* 0x000e */
            case tls_ext_heartbeat:                    /* 0x000f */
            case tls_ext_signed_certificate_timestamp: /* 0x0012 */
            case tls_ext_client_certificate_type:      /* 0x0013 */
            case tls_ext_server_certificate_type:      /* 0x0014 */
            case tls_ext_padding:                      /* 0x0015 */
            case tls_ext_encrypt_then_mac:             /* 0x0016 */
            case tls_ext_extended_master_secret:       /* 0x0017 */
            case tls_ext_record_size_limit:            /* 0x001c */
            case tls_ext_session_ticket:               /* 0x0023 */
            case tls_ext_tlmsp:                        /* 0x0024 */
            case tls_ext_cookie:                       /* 0x002c */
            case tls_ext_certificate_authorities:      /* 0x002f */
            case tls_ext_oid_filters:                  /* 0x0030 */
            case tls_ext_post_handshake_auth:          /* 0x0031 */
            case tls_ext_signature_algorithms_cert:    /* 0x0032 */
            default: {
                __try_new_catch_only(extension, new tls_extension_unknown(get_type(), handshake));
            } break;
        }
    }
    __finally2 {}
    return extension;
}

}  // namespace net
}  // namespace hotplace
