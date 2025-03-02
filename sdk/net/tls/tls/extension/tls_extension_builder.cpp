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

// #include <sdk/base/basic/types.hpp>
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
#include <sdk/net/tls/tls/tls.hpp>

namespace hotplace {
namespace net {

tls_extension_builder::tls_extension_builder() : _session(nullptr), _type(-1), _handshake(tls_hs_client_hello) {}

tls_extension_builder& tls_extension_builder::set(tls_session* session) {
    _session = session;
    return *this;
}

tls_extension_builder& tls_extension_builder::set(uint16 type) {
    _type = type;
    return *this;
}

tls_extension_builder& tls_extension_builder::set(tls_hs_type_t handshake) {
    _handshake = handshake;
    return *this;
}

tls_session* tls_extension_builder::get_session() { return _session; }

tls_hs_type_t tls_extension_builder::get_handshake() { return _handshake; }

tls_extension* tls_extension_builder::build() {
    tls_extension* extension = nullptr;
    switch (_type) {
        case tls1_ext_server_name: /* 0x0000 */ {
            __try_new_catch_only(extension, new tls_extension_sni(get_session()));
        } break;
        case tls1_ext_status_request: /* 0x0005 */ {
            __try_new_catch_only(extension, new tls_extension_status_request(get_session()));
        } break;
        case tls1_ext_supported_groups: /* 0x000a */ {
            __try_new_catch_only(extension, new tls_extension_supported_groups(get_session()));
        } break;
        case tls1_ext_ec_point_formats: /* 0x000b */ {
            __try_new_catch_only(extension, new tls_extension_ec_point_formats(get_session()));
        } break;
        case tls1_ext_signature_algorithms: /* 0x000d */ {
            __try_new_catch_only(extension, new tls_extension_signature_algorithms(get_session()));
        } break;
        case tls1_ext_application_layer_protocol_negotiation: /* 0x0010 */ {
            __try_new_catch_only(extension, new tls_extension_alpn(get_session()));
        } break;
        case tls1_ext_compress_certificate: /* 0x001b */ {
            __try_new_catch_only(extension, new tls_extension_compress_certificate(get_session()));
        } break;
        case tls1_ext_pre_shared_key: /* 0x0029 */ {
            auto session = get_session();
            if (session) {
                auto hstype = get_handshake();
                if (tls_hs_client_hello == hstype) {
                    __try_new_catch_only(extension, new tls_extension_client_psk(get_session()));
                } else if (tls_hs_server_hello == hstype) {
                    __try_new_catch_only(extension, new tls_extension_server_psk(get_session()));
                }
            }
        } break;
        case tls1_ext_supported_versions: /* 0x002b */ {
            auto session = get_session();
            if (session) {
                auto hstype = get_handshake();
                if (tls_hs_client_hello == hstype) {
                    __try_new_catch_only(extension, new tls_extension_client_supported_versions(get_session()));
                } else if (tls_hs_server_hello == hstype) {
                    __try_new_catch_only(extension, new tls_extension_server_supported_versions(get_session()));
                }
            }
        } break;
        case tls1_ext_psk_key_exchange_modes: /* 0x002d */ {
            __try_new_catch_only(extension, new tls_extension_psk_key_exchange_modes(get_session()));
        } break;
        case tls1_ext_key_share: /* 0x0033 */ {
            auto session = get_session();
            if (session) {
                auto hstype = get_handshake();
                if (tls_hs_client_hello == hstype) {
                    __try_new_catch_only(extension, new tls_extension_client_key_share(get_session()));
                } else if (tls_hs_server_hello == hstype) {
                    __try_new_catch_only(extension, new tls_extension_server_key_share(get_session()));
                }
            }
        } break;
        case tls1_ext_quic_transport_parameters: /* 0x0039 */ {
            __try_new_catch_only(extension, new tls_extension_quic_transport_parameters(get_session()));
        } break;
        case tls1_ext_application_layer_protocol_settings: /* 0x4469 */ {
            __try_new_catch_only(extension, new tls_extension_alps(get_session()));
        } break;
        case tls1_ext_encrypted_client_hello: /* 0xfe0d */ {
            __try_new_catch_only(extension, new tls_extension_encrypted_client_hello(get_session()));
        } break;

        case tls1_ext_max_fragment_length:          /* 0x0001 */
        case tls1_ext_client_certificate_url:       /* 0x0002 */
        case tls1_ext_use_srtp:                     /* 0x000e */
        case tls1_ext_heartbeat:                    /* 0x000f */
        case tls1_ext_signed_certificate_timestamp: /* 0x0012 */
        case tls1_ext_client_certificate_type:      /* 0x0013 */
        case tls1_ext_server_certificate_type:      /* 0x0014 */
        case tls1_ext_padding:                      /* 0x0015 */
        case tls1_ext_encrypt_then_mac:             /* 0x0016 */
        case tls1_ext_extended_master_secret:       /* 0x0017 */
        case tls1_ext_record_size_limit:            /* 0x001c */
        case tls1_ext_session_ticket:               /* 0x0023 */
        case tls1_ext_tlmsp:                        /* 0x0024 */
        case tls1_ext_early_data:                   /* 0x002a */
        case tls1_ext_cookie:                       /* 0x002c */
        case tls1_ext_certificate_authorities:      /* 0x002f */
        case tls1_ext_oid_filters:                  /* 0x0030 */
        case tls1_ext_post_handshake_auth:          /* 0x0031 */
        case tls1_ext_signature_algorithms_cert:    /* 0x0032 */
        case tls1_ext_renegotiation_info:           /* 0xff01 */
        default: {
            __try_new_catch_only(extension, new tls_extension_unknown(_type, get_session()));
        } break;
    }
    return extension;
}

}  // namespace net
}  // namespace hotplace
