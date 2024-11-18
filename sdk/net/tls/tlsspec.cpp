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
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tlsspec.hpp>

namespace hotplace {
namespace net {

// step.1 ... understanding TLS Record

static return_t tls_dump_client_hello(stream_t* s, const byte_t* stream, size_t size, size_t& pos);
static return_t tls_dump_server_hello(stream_t* s, const byte_t* stream, size_t size, size_t& pos);
static return_t tls_dump_extension(stream_t* s, const byte_t* stream, size_t size, size_t& pos);

return_t tls_dump_record(stream_t* s, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (size < 5) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        tls_resource* resource = tls_resource::get_instance();

        constexpr char constexpr_content_type[] = "content type";
        constexpr char constexpr_record_version[] = "legacy record version";
        constexpr char constexpr_len[] = "len";

        payload pl;
        pl << new payload_member(uint8(0), constexpr_content_type) << new payload_member(uint16(0), true, constexpr_record_version)
           << new payload_member(uint16(0), true, constexpr_len);
        pl.read(stream, size, pos);

        auto content_type = t_to_int<uint8>(pl.select(constexpr_content_type));
        auto protocol_version = t_to_int<uint16>(pl.select(constexpr_record_version));
        auto len = t_to_int<uint16>(pl.select(constexpr_len));

        s->autoindent(2);
        s->printf("# TLS Record\n");
        s->printf("> content type %i\n", content_type);
        s->printf("> %s 0x%02x (%s)\n", constexpr_record_version, protocol_version, resource->tls_version_string(protocol_version).c_str());
        s->autoindent(0);
        s->printf("> %s 0x%04x\n", constexpr_len, len);

        size_t tpos = 0;
        switch (content_type) {
            case tls_content_type_invalid: {
            } break;
            case tls_content_type_change_cipher_spec: {
            } break;
            case tls_content_type_alert: {
            } break;
            case tls_content_type_handshake: {
                ret = tls_dump_handshake(s, stream + pos, size - pos, tpos);
            } break;
            case tls_content_type_application_data: {
            } break;
        }
        pos += tpos;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_handshake(stream_t* s, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (size < 4) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        // RFC 8446 5.1.  Record Layer
        tls_handshake_t* handshake = (tls_handshake_t*)stream;
        uint32 length = 0;
        b24_i32(handshake->length, length);
        if (size < 4 + length) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        s->autoindent(3);
        s->printf(" > handshake type %i\n", handshake->msg_type);
        s->autoindent(0);
        s->printf(" > length %i\n", length);

        pos += sizeof(tls_handshaketype_t) + sizeof(uint24_t);

        /* 5.2.  Record Payload Protection */
        // TODO

        switch (handshake->msg_type) {
            case tls_handshake_client_hello: {
                ret = tls_dump_client_hello(s, stream, size, pos);
            } break;
            case tls_handshake_server_hello: {
                ret = tls_dump_server_hello(s, stream, size, pos);
            } break;
            case tls_handshake_new_session_ticket: {
                //
            } break;
            case tls_handshake_end_of_early_data: {
                //
            } break;
            case tls_handshake_encrypted_extensions: {
                //
            } break;
            case tls_handshake_certificate: {
                //
            } break;
            case tls_handshake_certificate_request: {
                //
            } break;
            case tls_handshake_certificate_verify: {
                //
            } break;
            case tls_handshake_finished: {
                //
            } break;
            case tls_handshake_key_update: {
                //
            } break;
            case tls_handshake_message_hash: {
                //
            } break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_client_hello(stream_t* s, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        constexpr char constexpr_version[] = "version";
        constexpr char constexpr_random[] = "random";
        constexpr char constexpr_session_id[] = "session id";
        constexpr char constexpr_session_ids[] = "session ids";
        constexpr char constexpr_cipher_suite[] = "cipher suite";
        constexpr char constexpr_cipher_suites[] = "cipher suites";
        constexpr char constexpr_compression_methods[] = "compression methods";
        constexpr char constexpr_compression_method[] = "compression method";
        constexpr char constexpr_extensions[] = "extension len";
        constexpr char constexpr_extension[] = "extension";

        /* RFC 8446 4.1.2.  Client Hello
         *  uint16 ProtocolVersion;
         *  opaque Random[32];
         *
         *  uint8 CipherSuite[2];    // Cryptographic suite selector
         *
         *  struct {
         *      ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
         *      Random random;
         *      opaque legacy_session_id<0..32>;
         *      CipherSuite cipher_suites<2..2^16-2>;
         *      opaque legacy_compression_methods<1..2^8-1>;
         *      Extension extensions<8..2^16-1>;
         *  } ClientHello;
         */

        uint16 version = 0;
        {
            payload plver;
            plver << new payload_member(uint16(0), true, constexpr_version);
            plver.read(stream, size, pos);

            version = t_to_int<uint16>(plver.select(constexpr_version));

            if (version < 0x0303) {
                // RFC 8996
                ret = errorcode_t::not_supported;
                __leave2;
            }
        }

        payload pl;
        pl << new payload_member(binary_t(), constexpr_random) << new payload_member(uint8(0), constexpr_session_ids)
           << new payload_member(binary_t(), constexpr_session_id) << new payload_member(uint16(0), true, constexpr_cipher_suites)
           << new payload_member(binary_t(), constexpr_cipher_suite) << new payload_member(uint8(0), constexpr_compression_methods)
           << new payload_member(binary_t(), constexpr_compression_method) << new payload_member(uint16(0), true, constexpr_extensions);

        pl.select(constexpr_random)->reserve(32);
        pl.set_reference_value(constexpr_session_id, constexpr_session_ids);
        pl.set_reference_value(constexpr_cipher_suite, constexpr_cipher_suites);
        pl.set_reference_value(constexpr_compression_method, constexpr_compression_methods);
        pl.set_reference_value(constexpr_extensions, constexpr_extension);
        pl.read(stream, size, pos);

        binary_t random;
        binary_t session_id;
        binary_t cipher_suite;
        binary_t compression_method;
        pl.select(constexpr_random)->get_variant().to_binary(random);
        uint8 session_ids = t_to_int<uint8>(pl.select(constexpr_session_ids));
        pl.select(constexpr_session_id)->get_variant().to_binary(session_id);
        uint16 cipher_suites = t_to_int<uint16>(pl.select(constexpr_cipher_suites)) >> 1;  // bytes / sizeof(uint16)
        pl.select(constexpr_cipher_suite)->get_variant().to_binary(cipher_suite);
        uint8 compression_methods = t_to_int<uint8>(pl.select(constexpr_compression_methods));
        pl.select(constexpr_compression_method)->get_variant().to_binary(compression_method);
        uint8 extension_len = t_to_int<uint16>(pl.select(constexpr_extensions));

        tls_resource* resource = tls_resource::get_instance();

        s->autoindent(4);
        s->printf("> ClientHello\n");
        s->printf(" > %s %04x (%s)\n", constexpr_version, version, resource->tls_version_string(version).c_str());
        s->printf(" > %s\n", constexpr_random);
        dump_memory(random, s, 16, 3, 0x0, dump_notrunc);
        s->printf("\n");
        s->printf(" > %s %i\n", constexpr_session_ids, session_ids);
        s->printf(" > %s %i\n", constexpr_cipher_suites, cipher_suites);
        for (auto i = 0; i < cipher_suites; i++) {
            auto cs = t_binary_to_integer2<uint16>(&cipher_suite[i << 1], sizeof(uint16));
            s->printf("   0x%04x %s\n", cs, resource->cipher_suite_string(cs).c_str());
        }
        s->printf(" > %s %i\n", constexpr_compression_methods, compression_methods);
        for (auto i = 0; i < compression_methods; i++) {
            auto compr = t_binary_to_integer2<uint8>(&compression_method[i], sizeof(uint8));
            s->printf("   0x%02x %s\n", compr, resource->compression_method_string(compr).c_str());
        }
        s->autoindent(0);
        s->printf(" > %s %i(0x%02x)\n", constexpr_extensions, extension_len, extension_len);

        while (errorcode_t::success == tls_dump_extension(s, stream, size, pos)) {
        };
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_server_hello(stream_t* s, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        constexpr char constexpr_version[] = "version";
        constexpr char constexpr_random[] = "random";
        constexpr char constexpr_session_id[] = "session id";
        constexpr char constexpr_cipher_suite[] = "cipher suite";
        constexpr char constexpr_compression_method[] = "compression method";
        constexpr char constexpr_extensions[] = "extension len";
        constexpr char constexpr_extension[] = "extension";

        /* RFC 8446 4.1.3.  Server Hello */

        uint16 version = 0;
        {
            payload plver;
            plver << new payload_member(uint16(0), true, constexpr_version);
            plver.read(stream, size, pos);

            version = t_to_int<uint16>(plver.select(constexpr_version));

            if (version < 0x0303) {
                // RFC 8996
                // TLS 1.0, 1.1
                ret = errorcode_t::not_supported;
                __leave2;
            }
        }

        payload pl;
        pl << new payload_member(binary_t(), constexpr_random) << new payload_member(uint8(0), constexpr_session_id)
           << new payload_member(uint16(0), true, constexpr_cipher_suite) << new payload_member(uint8(0), constexpr_compression_method)
           << new payload_member(uint16(0), true, constexpr_extensions);

        pl.select(constexpr_random)->reserve(32);
        pl.read(stream, size, pos);

        binary_t random;
        pl.select(constexpr_random)->get_variant().to_binary(random);
        uint8 session_id = t_to_int<uint8>(pl.select(constexpr_session_id));
        uint16 cipher_suite = t_to_int<uint16>(pl.select(constexpr_cipher_suite));
        uint8 compression_method = t_to_int<uint8>(pl.select(constexpr_compression_method));
        uint8 extension_len = t_to_int<uint16>(pl.select(constexpr_extensions));

        tls_resource* resource = tls_resource::get_instance();

        s->autoindent(4);
        s->printf("> ServerHello\n");
        s->printf(" > %s %04x (%s)\n", constexpr_version, version, resource->tls_version_string(version).c_str());
        s->printf(" > %s\n", constexpr_random);
        dump_memory(random, s, 16, 3, 0x0, dump_notrunc);
        s->printf("\n");
        s->printf(" > %s %i\n", constexpr_session_id, session_id);
        s->printf(" > %s 0x%04x %s\n", constexpr_cipher_suite, cipher_suite, resource->cipher_suite_string(cipher_suite).c_str());
        s->printf(" > %s %i %s\n", constexpr_compression_method, compression_method, resource->compression_method_string(compression_method).c_str());
        s->autoindent(0);
        s->printf(" > %s %i(0x%02x)\n", constexpr_extensions, extension_len, extension_len);

        while (errorcode_t::success == tls_dump_extension(s, stream, size, pos)) {
        };
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

static return_t tls_dump_extension(stream_t* s, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t begin = pos;

        tls_resource* resource = tls_resource::get_instance();

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
        size_t tpos = pos;
        switch (extension_type) {
            // RFC 6066 3.  Server Name Indication
            case tls_extension_server_name: {  // 0x0000
                s->autoindent(6);
                s->printf("> %s - server name\n", constexpr_extension);

                uint16 first_entry_len = 0;
                {
                    constexpr char constexpr_entry_len[] = "entry len";
                    payload pl;
                    pl << new payload_member(uint16(0), true, constexpr_entry_len);
                    pl.read(stream, size, pos);

                    first_entry_len = t_to_int<uint16>(pl.select(constexpr_entry_len));

                    s->printf(" > %s %i\n", constexpr_ext_len, ext_len);
                    s->printf(" > %s %i\n", constexpr_entry_len, first_entry_len);
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
                    s->printf(" > %s %i\n", constexpr_hostname_len, hostname_len);
                    dump_memory(hostname, s, 16, 3, 0x0, dump_notrunc);
                    s->printf("\n");
                }

                s->autoindent(0);
                s->printf("\n");
            } break;
            case tls_extension_supported_groups: {
                // RFC 8422 5.  Data Structures and Computations
                //  struct {
                //      NamedCurve named_curve_list<2..2^16-1>
                //  } NamedCurveList;
                s->autoindent(6);
                s->printf("> %s - supported groups\n", constexpr_extension);

                constexpr char constexpr_curves[] = "curves";
                constexpr char constexpr_curve[] = "curve";

                payload pl;
                pl << new payload_member(uint16(0), true, constexpr_curves) << new payload_member(binary_t(0), constexpr_curve);
                pl.set_reference_value(constexpr_curve, constexpr_curves);
                pl.read(stream, size, pos);

                binary_t named_curve;
                uint16 curves = t_to_int<uint16>(pl.select(constexpr_curves)) >> 1;
                pl.select(constexpr_curve)->get_variant().to_binary(named_curve);

                s->printf(" > %s %i\n", constexpr_ext_len, ext_len);
                s->printf(" > %s %i\n", constexpr_curves, curves);
                for (auto i = 0; i < curves; i++) {
                    auto curve = t_binary_to_integer2<uint16>(&named_curve[i << 1], sizeof(uint16));
                    s->printf("   0x%04x(%i) %s\n", curve, curve, resource->named_curve_string(curve).c_str());
                }

                s->autoindent(0);
                s->printf("\n");
            } break;
            case tls_extension_signature_algorithms: {
                // RFC 8446 4.2.3.  Signature Algorithms

                s->autoindent(6);
                s->printf("> %s - signature algorithms\n", constexpr_extension);

                constexpr char constexpr_algorithms[] = "algorithms";
                constexpr char constexpr_algorithm[] = "algorithm";

                payload pl;
                pl << new payload_member(uint16(0), true, constexpr_algorithms) << new payload_member(binary_t(), constexpr_algorithm);
                pl.set_reference_value(constexpr_algorithm, constexpr_algorithms);
                pl.read(stream, size, pos);

                binary_t algorithm;
                uint16 algorithms = t_to_int<uint16>(pl.select(constexpr_algorithms)) >> 1;
                pl.select(constexpr_algorithm)->get_variant().to_binary(algorithm);

                s->printf(" > %s %i\n", constexpr_ext_len, ext_len);
                s->printf(" > %s %i\n", constexpr_algorithms, algorithms);
                for (auto i = 0; i < algorithms; i++) {
                    auto alg = t_binary_to_integer2<uint16>(&algorithm[i << 1], sizeof(uint16));
                    s->printf("   0x%04x %s\n", alg, resource->signature_scheme_string(alg).c_str());
                }

                s->autoindent(0);
                s->printf("\n");
            } break;
            case tls_extension_application_layer_protocol_negotiation: {
                // RFC 7301
                s->autoindent(6);
                s->printf("> %s - ALPN\n", constexpr_extension);

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

                s->printf(" > %s %i\n", constexpr_ext_len, ext_len);
                s->printf(" > %s %i\n", constexpr_alpn_len, alpn_len);
                s->printf(" > %s %i\n", constexpr_protocol_len, proto_len);
                s->printf(" > %s\n", constexpr_protocol);
                dump_memory(protocol, s, 16, 3, 0x0, dump_notrunc);

                s->autoindent(0);
                s->printf("\n");
            } break;
#if 0
            case tls_extension_max_fragment_length: {
                //
            } break;
            case tls_extension_status_request: {
                //
            } break;
            case tls_extension_use_srtp: {
                //
            } break;
            case tls_extension_heartbeat: {
                //
            } break;
            case tls_extension_signed_certificate_timestamp: {
                //
            } break;
            case tls_extension_client_certificate_type: {
                //
            } break;
            case tls_extension_server_certificate_type: {
                //
            } break;
            case tls_extension_padding: {
                //
            } break;
            case tls_extension_pre_shared_key: {
                //
            } break;
            case tls_extension_early_data: {
                //
            } break;
            case tls_extension_supported_versions: {
                //
            } break;
            case tls_extension_cookie: {
                //
            } break;
            case tls_extension_psk_key_exchange_modes: {
                //
            } break;
            case tls_extension_certificate_authorities: {
                //
            } break;
            case tls_extension_oid_filters: {
                //
            } break;
            case tls_extension_post_handshake_auth: {
                //
            } break;
            case tls_extension_signature_algorithms_cert: {
                //
            } break;
            case tls_extension_key_share: {
                // RFC 8446 4.2.8.  Key Share
                //  struct {
                //      NamedGroup group;
                //      opaque key_exchange<1..2^16-1>;
                //  } KeyShareEntry;
                uint8 msg_type = stream[0];
                switch (msg_type) {
                    case tls_handshake_client_hello: {
                    //  struct {
                    //      KeyShareEntry client_shares<0..2^16-1>;
                    //  } KeyShareClientHello;
                    } break;
                    case tls_handshake_server_hello: {
                    //  struct {
                    //      KeyShareEntry server_share;
                    //  } KeyShareServerHello;
                    } break;
                }

            } break;
            case ls_extension_quic_transport_parameters: {
                // RFC 9001 8.2.  QUIC Transport Parameters Extension
            } break;
#endif
            default:
                s->autoindent(0);
                s->printf("### studying %04x @handshake[0x%08x]\n", extension_type, (uint64)begin);
                // ret = errorcode_t::not_supported;
                pos += ext_len;
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
