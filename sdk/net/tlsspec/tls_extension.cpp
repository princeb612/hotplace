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
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/quic/quic.hpp>
#include <sdk/net/tlsspec/tlsspec.hpp>

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
        if (pos >= size) {
            ret = errorcode_t::no_data;
            __leave2;
        }

        size_t begin = pos;

        tls_advisor* resource = tls_advisor::get_instance();

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

            extension_type = t_to_int<uint16>(pl.select(constexpr_extension_type));
            ext_len = t_to_int<uint16>(pl.select(constexpr_ext_len));
        }

        s->autoindent(3);
        s->printf("> %s - %04x %s\n", constexpr_extension, extension_type, resource->tls_extension_string(extension_type).c_str());
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
                while (pos < tpos + ext_len) {
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
                    payload server_name_list;
                    server_name_list << new payload_member(uint8(0), constexpr_name_type) << new payload_member(uint16(0), true, constexpr_hostname_len)
                                     << new payload_member(binary_t(), constexpr_hostname);
                    server_name_list.set_reference_value(constexpr_hostname, constexpr_hostname_len);
                    server_name_list.read(stream, size, pos);

                    uint8 type = t_to_int<uint8>(server_name_list.select(constexpr_name_type));
                    uint16 hostname_len = t_to_int<uint16>(server_name_list.select(constexpr_hostname_len));
                    binary_t hostname;
                    server_name_list.select(constexpr_hostname)->get_variant().to_binary(hostname);

                    s->printf(" > %s %i (%s)\n", constexpr_name_type, type, resource->sni_nametype_string(type).c_str());  // 00 host_name
                    s->printf(" > %s %s\n", constexpr_hostname, bin2str(hostname).c_str());
                }

            } break;
            case tls_extension_max_fragment_length: /* 0x0001 */ {
                // studying
                pos += ext_len;
            } break;
            case tls_extension_status_request: /* 0x0005 */ {
                // studying
                pos += ext_len;
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

                binary_t named_curve;
                uint16 curves = t_to_int<uint16>(pl.select(constexpr_curves)) >> 1;
                pl.select(constexpr_curve)->get_variant().to_binary(named_curve);

                s->printf(" > %s %i\n", constexpr_curves, curves);
                for (auto i = 0; i < curves; i++) {
                    auto curve = t_binary_to_integer<uint16>(&named_curve[i << 1], sizeof(uint16));
                    s->printf("   0x%04x(%i) %s\n", curve, curve, resource->named_curve_string(curve).c_str());
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
                uint8 len = t_to_int<uint8>(pl.select(constexpr_len));
                pl.select(constexpr_formats)->get_variant().to_binary(formats);

                s->printf(" > %s %i\n", constexpr_formats, len);
                for (auto i = 0; i < len; i++) {
                    auto fmt = formats[i];
                    s->printf("   0x%02x(%i) %s\n", fmt, fmt, resource->ec_point_format_string(fmt).c_str());
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
                uint16 algorithms = t_to_int<uint16>(pl.select(constexpr_algorithms)) >> 1;
                pl.select(constexpr_algorithm)->get_variant().to_binary(algorithm);

                s->printf(" > %s %i\n", constexpr_algorithms, algorithms);
                for (auto i = 0; i < algorithms; i++) {
                    auto alg = t_binary_to_integer<uint16>(&algorithm[i << 1], sizeof(uint16));
                    s->printf("   0x%04x %s\n", alg, resource->signature_scheme_string(alg).c_str());
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
                constexpr char constexpr_protocol_len[] = "alpn protocol len";
                constexpr char constexpr_protocol[] = "alpn protocol";

                payload pl;
                pl << new payload_member(uint16(0), true, constexpr_alpn_len) << new payload_member(uint8(0), constexpr_protocol_len)
                   << new payload_member(binary_t(0), constexpr_protocol);
                pl.set_reference_value(constexpr_protocol, constexpr_protocol_len);
                pl.read(stream, size, pos);

                uint16 alpn_len = t_to_int<uint16>(pl.select(constexpr_alpn_len));
                uint8 proto_len = t_to_int<uint16>(pl.select(constexpr_protocol_len));
                binary_t protocol;
                pl.select(constexpr_protocol)->get_variant().to_binary(protocol);

                s->printf(" > %s %i\n", constexpr_protocol_len, proto_len);
                s->printf(" > %s %s\n", constexpr_protocol, bin2str(protocol).c_str());

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
                // RFC 8446 4.2.9.  Pre-Shared Key Exchange Modes (psk_ke)
                pos += ext_len;
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
                        uint16 versions = t_to_int<uint8>(pl.select(constexpr_versions)) >> 1;
                        pl.select(constexpr_version)->get_variant().to_binary(version);

                        s->printf(" > %s %i\n", constexpr_versions, versions);
                        for (auto i = 0; i < versions; i++) {
                            auto ver = t_binary_to_integer<uint16>(&version[i << 1], sizeof(uint16));
                            s->printf("   0x%04x %s\n", ver, resource->tls_version_string(ver).c_str());
                        }
                    } break;
                    case tls_handshake_server_hello: {
                        payload pl;
                        pl << new payload_member(uint16(0), true, constexpr_version);
                        pl.read(stream, size, pos);

                        uint16 ver = t_to_int<uint16>(pl.select(constexpr_version));
                        s->printf(" > 0x%04x %s\n", ver, resource->tls_version_string(ver).c_str());
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

                uint8 modes = t_to_int<uint8>(pl.select(constexpr_modes));
                binary_t mode;
                pl.select(constexpr_mode)->get_variant().to_binary(mode);

                s->printf(" > %s\n", constexpr_modes);
                for (auto i = 0; i < modes; i++) {
                    auto m = mode[i];
                    s->printf("   %i %s\n", m, resource->psk_key_exchange_mode_string(m).c_str());
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
                // RFC 8446 4.2.8.  Key Share
                // RFC 8446 4.2.9.  Pre-Shared Key Exchange Modes (psk_dhe_ke)

                constexpr char constexpr_len[] = "len";
                constexpr char constexpr_group[] = "group";
                constexpr char constexpr_pubkey_len[] = "public key len";
                constexpr char constexpr_pubkey[] = "public key";

                //  struct {
                //      NamedGroup group;
                //      opaque key_exchange<1..2^16-1>;
                //  } KeyShareEntry;
                switch (hstype) {
                    case tls_handshake_client_hello: {
                        //  struct {
                        //      KeyShareEntry client_shares<0..2^16-1>;
                        //  } KeyShareClientHello;
                        while (pos < tpos + ext_len) {
                            payload pl;
                            pl << new payload_member(uint16(0), true, constexpr_len) << new payload_member(uint16(0), true, constexpr_group)
                               << new payload_member(uint16(0), true, constexpr_pubkey_len) << new payload_member(binary_t(), constexpr_pubkey);
                            pl.set_reference_value(constexpr_pubkey, constexpr_pubkey_len);
                            pl.read(stream, size, pos);

                            uint16 group = t_to_int<uint16>(pl.select(constexpr_group));
                            uint16 pubkeylen = t_to_int<uint16>(pl.select(constexpr_pubkey_len));
                            binary_t pubkey;
                            pl.select(constexpr_pubkey)->get_variant().to_binary(pubkey);

                            s->printf(" > %s 0x%04x (%s)\n", constexpr_group, group, resource->named_curve_string(group).c_str());
                            s->printf(" > %s %i\n", constexpr_pubkey_len, pubkeylen);
                            dump_memory(pubkey, s, 16, 3, 0x0, dump_notrunc);
                            s->printf("\n");
                            s->printf("   %s\n", base16_encode(pubkey).c_str());

                            auto& keyshare = session->get_tls_protection().get_keyexchange();
                            crypto_keychain keychain;
                            switch (group) {
                                case 0x0017: /* secp256r1 */ {
                                } break;
                                case 0x0018: /* secp384r1 */ {
                                } break;
                                case 0x0019: /* secp521r1 */ {
                                } break;
                                case 0x001d: /* x25519 */ {
                                    keychain.add_ec(&keyshare, NID_X25519, pubkey, binary_t(), binary_t());
                                } break;
                                case 0x001e: /* x448 */ {
                                    keychain.add_ec(&keyshare, NID_X448, pubkey, binary_t(), binary_t());
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
                        }
                    } break;
                    case tls_handshake_server_hello: {
                        //  struct {
                        //      KeyShareEntry server_share;
                        //  } KeyShareServerHello;
                        payload pl;
                        pl << new payload_member(uint16(0), true, constexpr_group) << new payload_member(uint16(0), true, constexpr_pubkey_len)
                           << new payload_member(binary_t(), constexpr_pubkey);
                        pl.set_reference_value(constexpr_pubkey, constexpr_pubkey_len);
                        pl.read(stream, size, pos);

                        uint16 group = t_to_int<uint16>(pl.select(constexpr_group));
                        uint16 pubkeylen = t_to_int<uint16>(pl.select(constexpr_pubkey_len));
                        binary_t pubkey;
                        pl.select(constexpr_pubkey)->get_variant().to_binary(pubkey);

                        s->printf(" > %s 0x%04x (%s)\n", constexpr_group, group, resource->named_curve_string(group).c_str());
                        s->printf(" > %s %i\n", constexpr_pubkey_len, pubkeylen);
                        dump_memory(pubkey, s, 16, 3, 0x0, dump_notrunc);
                        s->printf("\n");
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
                            s->printf(R"( > %I64i (%s) "%s")", param_id, resource->quic_param_string(param_id).c_str(), bin2str(param).c_str());
                            s->printf("\n");
                            break;
                        default: {
                            size_t epos = 0;
                            uint64 value = 0;
                            quic_read_vle_int(&param[0], param.size(), epos, value);
                            s->printf(" > %I64i (%s) %I64i\n", param_id, resource->quic_param_string(param_id).c_str(), value);
                        } break;
                    }
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
                s->printf("### studying %04x @handshake[0x%08x]\n", extension_type, (uint64)begin);
                pos += ext_len;
                break;
        }

        s->autoindent(0);
        s->printf("\n");
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
