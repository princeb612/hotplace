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

#include <sdk/base/basic/binary.hpp>
#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/basic/template.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/openssl_kdf.hpp>
#include <sdk/crypto/crypto/crypto_hash.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/quic/quic.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>

namespace hotplace {
namespace net {

// step.1 ... understanding TLS Extension

return_t tls_dump_extension(tls_handshake_type_t hstype, stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (pos + 4 >= size) {
            ret = errorcode_t::no_more;
            __leave2;
        }

        size_t extpos = pos;

        auto& protection = session->get_tls_protection();

        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        constexpr char constexpr_extension[] = "extension";
        constexpr char constexpr_ext_len[] = "extension len";
        uint16 extension_type = 0;
        uint16 ext_len = 0;
        {
            constexpr char constexpr_extension_type[] = "extension type";
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_extension_type) << new payload_member(uint16(0), true, constexpr_ext_len);
            ret = pl.read(stream, size, pos);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            extension_type = pl.t_value_of<uint16>(constexpr_extension_type);
            ext_len = pl.t_value_of<uint16>(constexpr_ext_len);
        }

        if (size - pos < ext_len) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        s->autoindent(3);
        s->printf("> %s - %04x %s\n", constexpr_extension, extension_type, tlsadvisor->tls_extension_string(extension_type).c_str());
        s->printf(" > %s %i\n", constexpr_ext_len, ext_len);

        size_t tpos = pos;
        switch (extension_type) {
            case tls_extension_server_name: /* 0x0000 */ {
                // RFC 6066 3.  Server Name Indication

                uint16 first_entry_len = 0;
                {
                    constexpr char constexpr_entry_len[] = "entry len";
                    payload pl;
                    pl << new payload_member(uint16(0), true, constexpr_entry_len);
                    pl.read(stream, size, pos);
                }

                /* .. tpos + ext_len */
                // while (pos < tpos + ext_len) {
                /**
                 *  struct {
                 *      NameType name_type;
                 *      select (name_type) {
                 *          case host_name: HostName;
                 *      } name;
                 *  } ServerName;
                 *  enum {
                 *      host_name(0), (255)
                 *  } NameType;
                 *  opaque HostName<1..2^16-1>;
                 *  struct {
                 *      ServerName server_name_list<1..2^16-1>
                 *  } ServerNameList;
                 */
                constexpr char constexpr_name_type[] = "name type";
                constexpr char constexpr_hostname_len[] = "hostname len";
                constexpr char constexpr_hostname[] = "hostname";
                payload pl;
                pl << new payload_member(uint8(0), constexpr_name_type) << new payload_member(uint16(0), true, constexpr_hostname_len)
                   << new payload_member(binary_t(), constexpr_hostname);
                pl.set_reference_value(constexpr_hostname, constexpr_hostname_len);
                pl.read(stream, size, pos);

                uint8 type = pl.t_value_of<uint8>(constexpr_name_type);
                uint16 hostname_len = pl.t_value_of<uint16>(constexpr_hostname_len);
                binary_t hostname;
                pl.get_binary(constexpr_hostname, hostname);

                s->printf(" > %s %i (%s)\n", constexpr_name_type, type, tlsadvisor->sni_nametype_string(type).c_str());  // 00 host_name
                s->printf(" > %s %s\n", constexpr_hostname, bin2str(hostname).c_str());
                // }

            } break;
            case tls_extension_max_fragment_length: /* 0x0001 */ {
                // studying
                pos += ext_len;
            } break;
            case tls_extension_status_request: /* 0x0005 */ {
                constexpr char constexpr_cert_status_type[] = "certificate status type";
                constexpr char constexpr_responderid_info_len[] = "responderid information len";
                constexpr char constexpr_responderid_info[] = "responderid information";
                constexpr char constexpr_request_ext_info_len[] = "request extension information len";
                constexpr char constexpr_request_ext_info[] = "request extension information";
                payload pl;
                pl << new payload_member(uint8(0), constexpr_cert_status_type) << new payload_member(uint16(), true, constexpr_responderid_info_len)
                   << new payload_member(binary_t(), constexpr_responderid_info) << new payload_member(uint16(0), true, constexpr_request_ext_info_len)
                   << new payload_member(binary_t(), constexpr_request_ext_info);
                pl.set_reference_value(constexpr_responderid_info, constexpr_responderid_info_len);
                pl.set_reference_value(constexpr_request_ext_info, constexpr_request_ext_info_len);
                pl.read(stream, size, pos);

                uint8 cert_status_type = pl.t_value_of<uint8>(constexpr_cert_status_type);
                uint16 responderid_info_len = pl.t_value_of<uint8>(constexpr_responderid_info_len);
                uint16 request_ext_info_len = pl.t_value_of<uint8>(constexpr_request_ext_info_len);
                binary_t responderid_info;
                binary_t request_ext_info;
                pl.get_binary(constexpr_responderid_info, responderid_info);
                pl.get_binary(constexpr_request_ext_info, request_ext_info);
                s->printf(" > %s %i %s\n", constexpr_cert_status_type, cert_status_type, tlsadvisor->cert_status_type_string(cert_status_type).c_str());
                s->printf(" > %s %i\n", constexpr_responderid_info_len, responderid_info_len);
                dump_memory(responderid_info, s, 16, 3, 0x0, dump_notrunc);
                s->printf(" > %s %i\n", constexpr_request_ext_info_len, request_ext_info_len);
                dump_memory(request_ext_info, s, 16, 3, 0x0, dump_notrunc);
            } break;
            case tls_extension_supported_groups: /* 0x000a */ {
                // RFC 8422 5.  Data Structures and Computations
                //  struct {
                //      NamedCurve named_curve_list<2..2^16-1>
                //  } NamedCurveList;

                constexpr char constexpr_curves[] = "curves";
                constexpr char constexpr_curve[] = "curve";

                payload pl;
                pl << new payload_member(uint16(0), true, constexpr_curves) << new payload_member(binary_t(0), constexpr_curve);
                pl.set_reference_value(constexpr_curve, constexpr_curves);
                pl.read(stream, size, pos);

                binary_t supported_groups;
                uint16 curves = pl.t_value_of<uint16>(constexpr_curves) >> 1;
                pl.get_binary(constexpr_curve, supported_groups);

                s->printf(" > %s %i\n", constexpr_curves, curves);
                for (auto i = 0; i < curves; i++) {
                    auto curve = t_binary_to_integer<uint16>(&supported_groups[i << 1], sizeof(uint16));
                    s->printf("   [%i] 0x%04x(%i) %s\n", i, curve, curve, tlsadvisor->supported_group_string(curve).c_str());
                }
            } break;
            case tls_extension_ec_point_formats: /* 0x000b */ {
                // RFC 8422 5.1.2.  Supported Point Formats Extension
                // enum {
                //     uncompressed (0),
                //     deprecated (1..2),
                //     reserved (248..255)
                // } ECPointFormat;
                // struct {
                //     ECPointFormat ec_point_format_list<1..2^8-1>
                // } ECPointFormatList;

                constexpr char constexpr_len[] = "len";
                constexpr char constexpr_formats[] = "formats";

                payload pl;
                pl << new payload_member(uint8(0), constexpr_len) << new payload_member(binary_t(0), constexpr_formats);
                pl.set_reference_value(constexpr_formats, constexpr_len);
                pl.read(stream, size, pos);

                binary_t formats;
                uint8 len = pl.t_value_of<uint8>(constexpr_len);
                pl.get_binary(constexpr_formats, formats);

                s->printf(" > %s %i\n", constexpr_formats, len);
                for (auto i = 0; i < len; i++) {
                    auto fmt = formats[i];
                    s->printf("   [%i] 0x%02x(%i) %s\n", i, fmt, fmt, tlsadvisor->ec_point_format_string(fmt).c_str());
                }
            } break;
            case tls_extension_signature_algorithms: /* 0x000d */ {
                // RFC 8446 4.2.3.  Signature Algorithms

                constexpr char constexpr_algorithms[] = "algorithms";
                constexpr char constexpr_algorithm[] = "algorithm";

                payload pl;
                pl << new payload_member(uint16(0), true, constexpr_algorithms) << new payload_member(binary_t(), constexpr_algorithm);
                pl.set_reference_value(constexpr_algorithm, constexpr_algorithms);
                pl.read(stream, size, pos);

                binary_t algorithm;
                uint16 algorithms = pl.t_value_of<uint16>(constexpr_algorithms) >> 1;
                pl.get_binary(constexpr_algorithm, algorithm);

                s->printf(" > %s %i\n", constexpr_algorithms, algorithms);
                for (auto i = 0; i < algorithms; i++) {
                    auto alg = t_binary_to_integer<uint16>(&algorithm[i << 1], sizeof(uint16));
                    s->printf("   [%i] 0x%04x %s\n", i, alg, tlsadvisor->signature_scheme_string(alg).c_str());
                }

            } break;
            case tls_extension_use_srtp: /* 0x000e */ {
                // studying
                pos += ext_len;
            } break;
            case tls_extension_heartbeat: /* 0x000f */ {
                // studying
                pos += ext_len;
            } break;
            case tls_extension_application_layer_protocol_negotiation: /* 0x0010 */ {
                // RFC 7301

                constexpr char constexpr_alpn_len[] = "alpn len";
                constexpr char constexpr_protocol[] = "alpn protocol";

                payload pl;
                pl << new payload_member(uint16(0), true, constexpr_alpn_len) << new payload_member(binary_t(0), constexpr_protocol);
                pl.set_reference_value(constexpr_protocol, constexpr_alpn_len);
                pl.read(stream, size, pos);

                uint16 alpn_len = pl.t_value_of<uint16>(constexpr_alpn_len);
                binary_t protocol;
                pl.get_binary(constexpr_protocol, protocol);

                s->printf(" > %s %i\n", constexpr_alpn_len, alpn_len);
                dump_memory(protocol, s, 16, 3, 0x0, dump_notrunc);
            } break;
            case tls_extension_signed_certificate_timestamp: /* 0x0012 */ {
                // studying
                pos += ext_len;
            } break;
            case tls_extension_client_certificate_type: /* 0x0013 */ {
                // studying
                pos += ext_len;
            } break;
            case tls_extension_server_certificate_type: /* 0x0014 */ {
                // studying
                pos += ext_len;
            } break;
            case tls_extension_padding: /* 0x0015 */ {
                // studying
                pos += ext_len;
            } break;
            case tls_extension_encrypt_then_mac: /* 0x0016 */ {
                // RFC 7366
                pos += ext_len;
            } break;
            case tls_extension_extended_master_secret: /* 0x0017 */ {
                pos += ext_len;
            } break;
            case tls_extension_compress_certificate: /* 0x001b */ {
                constexpr char constexpr_algorithm_len[] = "algorithm len";
                constexpr char constexpr_algorithm[] = "algorithm";
                uint8 algorithm_len = 0;
                binary_t algorithm;
                {
                    payload pl;
                    pl << new payload_member(uint8(0), constexpr_algorithm_len) << new payload_member(binary_t(), constexpr_algorithm);
                    pl.set_reference_value(constexpr_algorithm, constexpr_algorithm_len);
                    pl.read(stream, size, pos);

                    algorithm_len = pl.t_value_of<uint8>(constexpr_algorithm_len);
                    pl.get_binary(constexpr_algorithm, algorithm);
                }
                {
                    s->printf(" > %s %i (%i)\n", constexpr_algorithm_len, algorithm_len, algorithm_len >> 1);
                    for (auto i = 0; i < algorithm_len / sizeof(uint16); i++) {
                        auto alg = t_binary_to_integer<uint16>(&algorithm[i << 1], sizeof(uint16));
                        s->printf("   [%i] 0x%04x %s\n", i, alg, tlsadvisor->cert_compression_algid_string(alg).c_str());
                    }
                }
            } break;
            case tls_extension_record_size_limit: /* 0x001c */ {
                // studying
                pos += ext_len;
            } break;
            case tls_extension_session_ticket: /* 0x0023 */ {
                // RFC 5077 4.  Recommended Ticket Construction
                // struct {
                //     opaque key_name[16];
                //     opaque iv[16];
                //     opaque encrypted_state<0..2^16-1>;
                //     opaque mac[32];
                // } ticket;
                pos += ext_len;
            } break;
            case tls_extension_TLMSP: /* 0x0024 */ {
                pos += ext_len;
            } break;
            case tls_extension_pre_shared_key: /* 0x0029 */ {
                // RFC 4279 Pre-Shared Key Ciphersuites for Transport Layer Security (TLS)
                // RFC 4785 Pre-Shared Key (PSK) Ciphersuites with NULL Encryption for Transport Layer Security (TLS)
                // RFC 5487 Pre-Shared Key Cipher Suites for TLS with SHA-256/384 and AES Galois Counter Mode
                // RFC 5489 ECDHE_PSK Cipher Suites for Transport Layer Security (TLS)
                //
                // RFC 8446 4.2.9.  Pre-Shared Key Exchange Modes (psk_ke)
                // RFC 8446 4.2.10.  Early Data Indication
                // RFC 8446 4.2.11.  Pre-Shared Key Extension
                //
                // struct {
                //     opaque identity<1..2^16-1>;
                //     uint32 obfuscated_ticket_age;
                // } PskIdentity;
                //
                // opaque PskBinderEntry<32..255>;
                //
                // struct {
                //     PskIdentity identities<7..2^16-1>;
                //     PskBinderEntry binders<33..2^16-1>;
                // } OfferedPsks;
                //
                // struct {
                //     select (Handshake.msg_type) {
                //         case client_hello: OfferedPsks;
                //         case server_hello: uint16 selected_identity;
                //     };
                // } PreSharedKeyExtension;
                //
                // RFC 9257 Guidance for External Pre-Shared Key (PSK) Usage in TLS

                switch (hstype) {
                    case tls_handshake_client_hello: {
                        constexpr char constexpr_psk_identities_len[] = "psk identities len";
                        constexpr char constexpr_psk_identity_len[] = "psk identity len";
                        constexpr char constexpr_psk_identity[] = "psk identity";
                        constexpr char constexpr_obfuscated_ticket_age[] = "obfuscated ticket age";
                        constexpr char constexpr_psk_binders_len[] = "psk binders len";
                        constexpr char constexpr_psk_binder_len[] = "psk binder len";
                        constexpr char constexpr_psk_binder[] = "psk binder";
                        uint16 psk_identities_len = 0;
                        uint16 psk_identity_len = 0;
                        binary_t psk_identity;
                        uint32 obfuscated_ticket_age = 0;
                        uint16 psk_binders_len = 0;
                        uint8 psk_binder_len = 0;
                        binary_t psk_binder;
                        openssl_kdf kdf;

                        size_t offset_psk_binders_len = 0;
                        {
                            payload pl;
                            pl << new payload_member(uint16(0), true, constexpr_psk_identities_len)
                               << new payload_member(uint16(0), true, constexpr_psk_identity_len) << new payload_member(binary_t(), constexpr_psk_identity)
                               << new payload_member(uint32(0), true, constexpr_obfuscated_ticket_age)
                               << new payload_member(uint16(0), true, constexpr_psk_binders_len) << new payload_member(uint8(0), constexpr_psk_binder_len)
                               << new payload_member(binary_t(), constexpr_psk_binder);
                            pl.set_reference_value(constexpr_psk_identity, constexpr_psk_identity_len);
                            pl.set_reference_value(constexpr_psk_binder, constexpr_psk_binder_len);
                            pl.read(stream, size, pos);

                            psk_identities_len = pl.t_value_of<uint16>(constexpr_psk_identities_len);
                            psk_identity_len = pl.t_value_of<uint16>(constexpr_psk_identity_len);
                            pl.get_binary(constexpr_psk_identity, psk_identity);
                            obfuscated_ticket_age = pl.t_value_of<uint32>(constexpr_obfuscated_ticket_age);
                            offset_psk_binders_len = extpos + pl.offset_of(constexpr_psk_binders_len);  // 0-RTT "res binder"
                            psk_binders_len = pl.t_value_of<uint16>(constexpr_psk_binders_len);
                            psk_binder_len = pl.t_value_of<uint8>(constexpr_psk_binder_len);
                            pl.get_binary(constexpr_psk_binder, psk_binder);
                        }
                        {
                            // RFC 8448 4.  Resumed 0-RTT Handshake

                            // binder hash
                            binary_t context_resumption_binder_hash;
                            {
                                size_t content_header_size = 0;
                                size_t sizeof_dtls_recons = 0;
                                if (protection.is_kindof_tls()) {
                                    content_header_size = RTL_FIELD_SIZE(tls_content_t, tls);
                                } else {
                                    content_header_size = RTL_FIELD_SIZE(tls_content_t, dtls);
                                    sizeof_dtls_recons = 8;
                                }
                                ret = protection.calc_context_hash(session, sha2_256, stream + content_header_size, offset_psk_binders_len - 1,
                                                                   context_resumption_binder_hash);
                                // if (errorcode_t::success != ret) do something
                            }

                            // verify psk binder
                            ret = protection.calc_psk(session, context_resumption_binder_hash, psk_binder);
                        }
                        {
                            s->printf(" > %s 0x%04x(%i)\n", constexpr_psk_identity_len, psk_identity_len, psk_identity_len);
                            dump_memory(psk_identity, s, 16, 3, 0x0, dump_notrunc);
                            s->printf(" > %s 0x%08x\n", constexpr_obfuscated_ticket_age, obfuscated_ticket_age);
                            s->printf(" > %s 0x%04x(%i) @0x%08x\n", constexpr_psk_binders_len, psk_binders_len, psk_binders_len, offset_psk_binders_len);
                            s->printf(" > %s 0x%04x(%i)\n", constexpr_psk_binder_len, psk_binder_len, psk_binder_len);
                            s->printf(" > %s %s \e[1;33m%s\e[0m\n", constexpr_psk_binder, base16_encode(psk_binder).c_str(),
                                      (errorcode_t::success == ret) ? "true" : "false");
                        }
                    } break;
                    case tls_handshake_server_hello: {
                        constexpr char constexpr_selected_identity[] = "selected identity";
                        uint16 selected_identity = 0;
                        {
                            payload pl;
                            pl << new payload_member(uint16(0), true, constexpr_selected_identity);
                            pl.read(stream, size, pos);

                            selected_identity = pl.t_value_of<uint16>(constexpr_selected_identity);
                        }
                        {
                            //
                            s->printf(" > %s %i\n", constexpr_selected_identity, selected_identity);
                        }
                    } break;
                }

            } break;
            case tls_extension_early_data: /* 0x002a */ {
                // studying
                pos += ext_len;
            } break;
            case tls_extension_supported_versions: /* 0x002b */ {
                // studying

                constexpr char constexpr_versions[] = "supported versions";
                constexpr char constexpr_version[] = "version";

                switch (hstype) {
                    case tls_handshake_client_hello: {
                        payload pl;
                        pl << new payload_member(uint8(0), constexpr_versions) << new payload_member(binary_t(), constexpr_version);
                        pl.set_reference_value(constexpr_version, constexpr_versions);
                        pl.read(stream, size, pos);

                        binary_t version;
                        uint16 versions = pl.t_value_of<uint8>(constexpr_versions) >> 1;
                        pl.get_binary(constexpr_version, version);

                        s->printf(" > %s %i\n", constexpr_versions, versions);
                        for (auto i = 0; i < versions; i++) {
                            auto ver = t_binary_to_integer<uint16>(&version[i << 1], sizeof(uint16));
                            s->printf("   [%i] 0x%04x %s\n", i, ver, tlsadvisor->tls_version_string(ver).c_str());
                        }
                    } break;
                    case tls_handshake_server_hello: {
                        payload pl;
                        pl << new payload_member(uint16(0), true, constexpr_version);
                        pl.read(stream, size, pos);

                        uint16 ver = pl.t_value_of<uint16>(constexpr_version);
                        s->printf(" > 0x%04x %s\n", ver, tlsadvisor->tls_version_string(ver).c_str());

                        protection.set_tls_version(ver);
                    } break;
                }

            } break;
            case tls_extension_cookie: /* 0x002c */ {
                // studying
                pos += ext_len;
            } break;
            case tls_extension_psk_key_exchange_modes: /* 0x002d */ {
                // RFC 8446 4.2.9.  Pre-Shared Key Exchange Modes
                // enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
                // struct {
                //     PskKeyExchangeMode ke_modes<1..255>;
                // } PskKeyExchangeModes;

                constexpr char constexpr_modes[] = "modes";
                constexpr char constexpr_mode[] = "mode";

                payload pl;
                pl << new payload_member(uint8(0), constexpr_modes) << new payload_member(binary_t(), constexpr_mode);
                pl.set_reference_value(constexpr_mode, constexpr_modes);
                pl.read(stream, size, pos);

                uint8 modes = pl.t_value_of<uint8>(constexpr_modes);
                binary_t mode;
                pl.get_binary(constexpr_mode, mode);

                s->printf(" > %s\n", constexpr_modes);
                for (auto i = 0; i < modes; i++) {
                    auto m = mode[i];
                    s->printf("   [%i] %i %s\n", i, m, tlsadvisor->psk_key_exchange_mode_string(m).c_str());
                }
            } break;
            case tls_extension_certificate_authorities: /* 0x002f */ {
                // studying
                pos += ext_len;
            } break;
            case tls_extension_oid_filters: /* 0x0030 */ {
                // studying
                pos += ext_len;
            } break;
            case tls_extension_post_handshake_auth: /* 0x0031 */ {
                // studying
                pos += ext_len;
            } break;
            case tls_extension_signature_algorithms_cert: /* 0x0032 */ {
                // studying
                pos += ext_len;
            } break;
            case tls_extension_key_share: /* 0x0033 */ {
                auto lambda_keyshare = [&](tls_session* session, uint16 group, const binary_t& pubkey, const keydesc& desc) -> void {
                    auto& keyshare = protection.get_keyexchange();
                    crypto_keychain keychain;
                    switch (group) {
                        // TODO ...
                        case 0x0017: /* secp256r1 */ {
                        } break;
                        case 0x0018: /* secp384r1 */ {
                        } break;
                        case 0x0019: /* secp521r1 */ {
                        } break;
                        case 0x001d: /* x25519 */ {
                            keychain.add_okp(&keyshare, NID_X25519, pubkey, binary_t(), desc);
                        } break;
                        case 0x001e: /* x448 */ {
                            keychain.add_okp(&keyshare, NID_X448, pubkey, binary_t(), desc);
                        } break;
                        case 0x0100: /* ffdhe2048 */ {
                        } break;
                        case 0x0101: /* ffdhe3072 */ {
                        } break;
                        case 0x0102: /* ffdhe4096 */ {
                        } break;
                        case 0x0103: /* ffdhe6144 */ {
                        } break;
                        case 0x0104: /* ffdhe8192 */ {
                        } break;
                    }
                };

                // RFC 8446 4.2.8.  Key Share
                // RFC 8446 4.2.9.  Pre-Shared Key Exchange Modes (psk_dhe_ke)

                constexpr char constexpr_key_share_entry[] = "key share entry";
                constexpr char constexpr_len[] = "len";
                constexpr char constexpr_group[] = "group";
                constexpr char constexpr_pubkey_len[] = "public key len";
                constexpr char constexpr_pubkey[] = "public key";

                uint16 group = 0;
                binary_t pubkey;
                keydesc desc;

                //  struct {
                //      NamedGroup group;
                //      opaque key_exchange<1..2^16-1>;
                //  } KeyShareEntry;
                switch (hstype) {
                    case tls_handshake_client_hello: {
                        desc.set_kid("CH");
                        //  struct {
                        //      KeyShareEntry client_shares<0..2^16-1>;
                        //  } KeyShareClientHello;
                        {
                            payload pl;
                            pl << new payload_member(uint16(0), true, constexpr_len);
                            pl.read(stream, size, pos);

                            uint16 len = 0;
                            len = pl.t_value_of<uint16>(constexpr_len);

                            s->printf(" > %s %i(0x%04x)\n", constexpr_len, len, len);
                        }
                        while (pos < tpos + ext_len) {
                            payload pl;
                            pl << new payload_member(uint16(0), true, constexpr_group) << new payload_member(uint16(0), true, constexpr_pubkey_len)
                               << new payload_member(binary_t(), constexpr_pubkey);
                            pl.set_reference_value(constexpr_pubkey, constexpr_pubkey_len);
                            pl.read(stream, size, pos);

                            group = pl.t_value_of<uint16>(constexpr_group);
                            uint16 pubkeylen = pl.t_value_of<uint16>(constexpr_pubkey_len);
                            pl.get_binary(constexpr_pubkey, pubkey, variant_trunc);

                            lambda_keyshare(session, group, pubkey, desc);

                            s->printf("  > %s\n", constexpr_key_share_entry);
                            s->printf("   > %s 0x%04x (%s)\n", constexpr_group, group, tlsadvisor->supported_group_string(group).c_str());
                            s->printf("   > %s %i(%04x)\n", constexpr_pubkey_len, pubkeylen, pubkeylen);
                            dump_memory(pubkey, s, 16, 5, 0x0, dump_notrunc);
                            s->printf("     %s\n", base16_encode(pubkey).c_str());
                        }
                    } break;
                    case tls_handshake_server_hello: {
                        desc.set_kid("SH");
                        //  struct {
                        //      KeyShareEntry server_share;
                        //  } KeyShareServerHello;
                        payload pl;
                        pl << new payload_member(uint16(0), true, constexpr_group) << new payload_member(uint16(0), true, constexpr_pubkey_len)
                           << new payload_member(binary_t(), constexpr_pubkey);
                        pl.set_reference_value(constexpr_pubkey, constexpr_pubkey_len);
                        pl.read(stream, size, pos);

                        group = pl.t_value_of<uint16>(constexpr_group);
                        uint16 pubkeylen = pl.t_value_of<uint16>(constexpr_pubkey_len);
                        pl.get_binary(constexpr_pubkey, pubkey);

                        lambda_keyshare(session, group, pubkey, desc);

                        s->printf(" > %s 0x%04x (%s)\n", constexpr_group, group, tlsadvisor->supported_group_string(group).c_str());
                        s->printf(" > %s %i\n", constexpr_pubkey_len, pubkeylen);
                        dump_memory(pubkey, s, 16, 3, 0x0, dump_notrunc);
                        s->printf("   %s\n", base16_encode(pubkey).c_str());
                    } break;
                }
            } break;
            case tls_extension_quic_transport_parameters: /* 0x0039 */ {
                // RFC 9001 8.2.  QUIC Transport Parameters Extension
                // studying

                // RFC 9000 18.  Transport Parameter Encoding
                constexpr char constexpr_param_id[] = "param id";
                constexpr char constexpr_param[] = "param";
                while (pos < tpos + ext_len) {
                    payload pl;
                    pl << new payload_member(new quic_encoded(uint64(0)), constexpr_param_id)
                       << new payload_member(new quic_encoded(binary_t()), constexpr_param);
                    pl.read(stream, size, pos);

                    binary_t param;
                    uint64 param_id = pl.select(constexpr_param_id)->get_payload_encoded()->value();
                    pl.select(constexpr_param)->get_payload_encoded()->get_variant().to_binary(param);
                    switch (param_id) {
                        case quic_param_initial_source_connection_id:
                        case quic_param_retry_source_connection_id:
                            s->printf(" > %I64i (%s)\n", param_id, tlsadvisor->quic_param_string(param_id).c_str());
                            dump_memory(param, s, 16, 5, 0x0, dump_notrunc);
                            break;
                        default: {
                            size_t epos = 0;
                            uint64 value = 0;
                            quic_read_vle_int(&param[0], param.size(), epos, value);
                            s->printf(" > %I64i (%s) %I64i\n", param_id, tlsadvisor->quic_param_string(param_id).c_str(), value);
                        } break;
                    }
                }

            } break;
            case tls_extension_application_layer_protocol_settings: /* 0x4469 */ {
                // ALPS
                constexpr char constexpr_alps_len[] = "alps len";
                constexpr char constexpr_alpn_len[] = "alpn len";
                constexpr char constexpr_alpn[] = "alpn";
                uint16 alps_len = 0;
                uint8 alpn_len = 0;
                binary_t alpn;
                {
                    payload pl;
                    pl << new payload_member(uint16(0), true, constexpr_alps_len) << new payload_member(binary_t(), constexpr_alpn);
                    pl.set_reference_value(constexpr_alpn, constexpr_alps_len);
                    pl.read(stream, size, pos);

                    alps_len = pl.t_value_of<uint16>(constexpr_alps_len);
                    pl.get_binary(constexpr_alpn, alpn);
                }
                {
                    s->printf(" > %s %i\n", constexpr_alps_len, alps_len);
                    dump_memory(alpn, s, 16, 3, 0x0, dump_notrunc);
                }
            } break;
            case tls_extension_encrypted_client_hello: /* 0xfe0d */ {
                constexpr char constexpr_client_hello_type[] = "client hello type";
                constexpr char constexpr_kdf[] = "kdf";
                constexpr char constexpr_aead[] = "aead";
                constexpr char constexpr_config_id[] = "config id";
                constexpr char constexpr_enc_len[] = "enc len";
                constexpr char constexpr_enc[] = "enc";
                constexpr char constexpr_payload_len[] = "payload len";
                constexpr char constexpr_payload[] = "payload";

                uint8 client_hello_type = 0;
                uint16 kdf = 0;
                uint16 aead = 0;
                uint8 config_id = 0;
                uint16 enc_len = 0;
                binary_t enc;
                uint16 enc_payload_len = 0;
                binary_t enc_payload;

                {
                    payload pl;
                    pl << new payload_member(uint8(0), constexpr_client_hello_type) << new payload_member(uint16(0), true, constexpr_kdf)
                       << new payload_member(uint16(0), true, constexpr_aead) << new payload_member(uint8(0), constexpr_config_id)
                       << new payload_member(uint16(0), true, constexpr_enc_len) << new payload_member(binary_t(), constexpr_enc)
                       << new payload_member(uint16(0), true, constexpr_payload_len) << new payload_member(binary_t(), constexpr_payload);
                    pl.set_reference_value(constexpr_enc, constexpr_enc_len);
                    pl.set_reference_value(constexpr_payload, constexpr_payload_len);
                    pl.read(stream, size, pos);

                    client_hello_type = pl.t_value_of<uint8>(constexpr_client_hello_type);
                    kdf = pl.t_value_of<uint16>(constexpr_kdf);
                    aead = pl.t_value_of<uint16>(constexpr_aead);
                    config_id = pl.t_value_of<uint8>(constexpr_config_id);
                    enc_len = pl.t_value_of<uint16>(constexpr_enc_len);
                    pl.get_binary(constexpr_enc, enc);
                    enc_payload_len = pl.t_value_of<uint16>(constexpr_payload_len);
                    pl.get_binary(constexpr_payload, enc_payload);
                }

                // TODO - decrypt

                {
                    s->printf(" > %s %i\n", constexpr_client_hello_type, client_hello_type);
                    s->printf(" > %s %i %s\n", constexpr_kdf, kdf, tlsadvisor->kdf_id_string(kdf).c_str());
                    s->printf(" > %s %i %s\n", constexpr_aead, aead, tlsadvisor->aead_alg_string(aead).c_str());
                    s->printf(" > %s %i\n", constexpr_config_id, config_id);
                    s->printf(" > %s %i\n", constexpr_enc_len, enc_len);
                    dump_memory(enc, s, 16, 3, 0x0, dump_notrunc);
                    s->printf(" > %s %i\n", constexpr_payload_len, enc_payload_len);
                    dump_memory(enc_payload, s, 16, 3, 0x0, dump_notrunc);
                }
            } break;
            case tls_extension_renegotiation_info: /* 0xff01 */ {
                // RFC 5746 3.2.  Extension Definition
                // struct {
                //     opaque renegotiated_connection<0..255>;
                // } RenegotiationInfo;
                pos += ext_len;
            } break;
            default:
                s->printf("### studying %04x @handshake[0x%08x]\n", extension_type, (uint64)extpos);
                pos += ext_len;
                break;
        }

        s->autoindent(0);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
