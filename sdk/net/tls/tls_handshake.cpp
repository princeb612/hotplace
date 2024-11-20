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
#include <sdk/net/quic/quic.hpp>
#include <sdk/net/tls/tlsspec.hpp>

namespace hotplace {
namespace net {

// step.1 ... understanding TLS Handshake

static return_t tls_dump_client_hello(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
static return_t tls_dump_server_hello(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);

return_t tls_dump_handshake(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
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

        auto type = handshake->msg_type;
        tls_advisor* resource = tls_advisor::get_instance();

        s->autoindent(3);
        s->printf(" > handshake type %i (%s)\n", type, resource->handshake_type_string(type).c_str());
        s->autoindent(0);
        s->printf(" > length 0x%04x(%i)\n", length, length);

        pos += sizeof(tls_handshake_type_t) + sizeof(uint24_t);

        /* 5.2.  Record Payload Protection */
        // TODO

        switch (handshake->msg_type) {
            case tls_handshake_client_hello: {
                ret = tls_dump_client_hello(s, session, stream, size, pos);
            } break;
            case tls_handshake_server_hello: {
                ret = tls_dump_server_hello(s, session, stream, size, pos);
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

return_t tls_dump_client_hello(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos) {
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

        tls_advisor* resource = tls_advisor::get_instance();

        s->autoindent(4);
        s->printf(" > %s 0x%04x (%s)\n", constexpr_version, version, resource->tls_version_string(version).c_str());
        s->printf(" > %s\n", constexpr_random);
        if (random.size()) {
            dump_memory(random, s, 16, 3, 0x0, dump_notrunc);
            s->printf("\n");
            s->printf("   %s\n", base16_encode(random).c_str());
        }
        s->printf(" > %s\n", constexpr_session_id);
        if (session_id.size()) {
            s->printf("   %s\n", base16_encode(session_id).c_str());
        }
        s->printf(" > %s %i\n", constexpr_cipher_suites, cipher_suites);
        for (auto i = 0; i < cipher_suites; i++) {
            auto cs = t_binary_to_integer<uint16>(&cipher_suite[i << 1], sizeof(uint16));
            s->printf("   0x%04x %s\n", cs, resource->cipher_suite_string(cs).c_str());
        }
        s->printf(" > %s %i\n", constexpr_compression_methods, compression_methods);
        for (auto i = 0; i < compression_methods; i++) {
            auto compr = t_binary_to_integer<uint8>(&compression_method[i], sizeof(uint8));
            s->printf("   0x%02x %s\n", compr, resource->compression_method_string(compr).c_str());
        }
        s->autoindent(0);
        s->printf(" > %s %i(0x%02x)\n", constexpr_extensions, extension_len, extension_len);

        while (errorcode_t::success == tls_dump_extension(s, session, stream, size, pos)) {
        };
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_server_hello(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        constexpr char constexpr_version[] = "version";
        constexpr char constexpr_random[] = "random";
        constexpr char constexpr_session_ids[] = "session ids";
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
        pl << new payload_member(binary_t(), constexpr_random) << new payload_member(uint8(0), constexpr_session_ids)
           << new payload_member(binary_t(), constexpr_session_id) << new payload_member(uint16(0), true, constexpr_cipher_suite)
           << new payload_member(uint8(0), constexpr_compression_method) << new payload_member(uint16(0), true, constexpr_extensions);

        pl.select(constexpr_random)->reserve(32);
        pl.set_reference_value(constexpr_session_id, constexpr_session_ids);
        pl.read(stream, size, pos);

        binary_t random;
        binary_t session_id;
        pl.select(constexpr_random)->get_variant().to_binary(random);
        uint8 session_ids = t_to_int<uint8>(pl.select(constexpr_session_ids));
        pl.select(constexpr_session_id)->get_variant().to_binary(session_id);
        uint16 cipher_suite = t_to_int<uint16>(pl.select(constexpr_cipher_suite));
        uint8 compression_method = t_to_int<uint8>(pl.select(constexpr_compression_method));
        uint8 extension_len = t_to_int<uint16>(pl.select(constexpr_extensions));

        tls_advisor* resource = tls_advisor::get_instance();

        s->autoindent(4);
        s->printf(" > %s 0x%04x (%s)\n", constexpr_version, version, resource->tls_version_string(version).c_str());
        s->printf(" > %s\n", constexpr_random);
        if (random.size()) {
            dump_memory(random, s, 16, 3, 0x0, dump_notrunc);
            s->printf("\n");
            s->printf("   %s\n", base16_encode(random).c_str());
        }
        s->printf(" > %s\n", constexpr_session_id);
        if (session_id.size()) {
            s->printf("   %s\n", base16_encode(session_id).c_str());
        }
        s->printf(" > %s 0x%04x %s\n", constexpr_cipher_suite, cipher_suite, resource->cipher_suite_string(cipher_suite).c_str());
        s->printf(" > %s %i %s\n", constexpr_compression_method, compression_method, resource->compression_method_string(compression_method).c_str());
        s->autoindent(0);
        s->printf(" > %s %i(0x%02x)\n", constexpr_extensions, extension_len, extension_len);

        session->set_cipher_suite(cipher_suite);

        while (errorcode_t::success == tls_dump_extension(s, session, stream, size, pos)) {
        };
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
