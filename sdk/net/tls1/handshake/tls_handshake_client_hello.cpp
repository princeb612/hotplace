/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_handshake.hpp>

namespace hotplace {
namespace net {

tls_handshake_client_hello::tls_handshake_client_hello(tls_session* session) : tls_handshake(tls_hs_client_hello, session) {}

return_t tls_handshake_client_hello::do_handshake(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
        auto hspos = get_header_range().begin;
        auto hdrsize = get_header_size();
        auto& protection = session->get_tls_protection();

        {
            auto hsstatus = session->get_session_info(dir).get_status();
            if (tls_hs_finished == hsstatus) {
                // 0-RTT
                protection.set_flow(tls_0_rtt);
            }
            switch (protection.get_flow()) {
                case tls_1_rtt: {
                } break;
                case tls_0_rtt: {
                    protection.get_keyexchange().clear();

                    session->reset_recordno(from_client);
                    session->reset_recordno(from_server);
                } break;
                case tls_hello_retry_request: {
                    auto& keyexchange = protection.get_keyexchange();
                    keyexchange.erase("CH");  // client_hello key_share
                    keyexchange.erase("SH");  // server_hello key_share
                } break;
                default: {
                } break;
            }

            ret = do_read(dir, stream, size, pos, debugstream);

            switch (protection.get_flow()) {
                case tls_1_rtt: {
                    // 1-RTT
                    protection.set_item(tls_context_client_hello, stream + hspos, hdrsize);  // transcript hash, see server_hello
                } break;
                case tls_0_rtt: {
                    protection.reset_transcript_hash(session);
                    protection.calc_transcript_hash(session, stream + hspos, hdrsize /*, handshake_hash */);  // client_hello
                    ret = protection.calc(session, tls_hs_client_hello, dir);
                } break;
                case tls_hello_retry_request: {
                    protection.calc_transcript_hash(session, stream + hspos, hdrsize /*, handshake_hash */);  // client_hello
                } break;
            }

            session->get_session_info(dir).set_status(get_type());
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_client_hello::do_read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

            constexpr char constexpr_version[] = "version";
            constexpr char constexpr_random[] = "random";
            constexpr char constexpr_session_id[] = "session id";
            constexpr char constexpr_session_id_len[] = "session id len";
            constexpr char constexpr_cipher_suite[] = "cipher suite";
            constexpr char constexpr_cipher_suite_len[] = "cipher suite len";
            constexpr char constexpr_compression_method_len[] = "compression method len";
            constexpr char constexpr_compression_method[] = "compression method";
            constexpr char constexpr_extension_len[] = "extension len";

            constexpr char constexpr_group_dtls[] = "dtls";
            constexpr char constexpr_cookie_len[] = "cookie len";
            constexpr char constexpr_cookie[] = "cookie";

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
             *      CipherSuite cipher_suite_len<2..2^16-2>;
             *      opaque legacy_compression_methods<1..2^8-1>;
             *      Extension extensions<8..2^16-1>;
             *  } ClientHello;
             */

            auto& protection = session->get_tls_protection();
            uint16 record_version = protection.get_record_version();
            uint16 version = 0;
            binary_t random;
            binary_t session_id;
            binary_t cipher_suite;
            binary_t compression_method;
            uint8 session_id_len = 0;
            uint16 cipher_suite_len = 0;
            uint8 compression_method_len = 0;
            uint16 extension_len = 0;

            {
                payload pl;
                pl << new payload_member(uint16(0), true, constexpr_version) << new payload_member(binary_t(), constexpr_random)
                   << new payload_member(uint8(0), constexpr_session_id_len) << new payload_member(binary_t(), constexpr_session_id)
                   << new payload_member(uint8(0), constexpr_cookie_len, constexpr_group_dtls)  // dtls
                   << new payload_member(binary_t(), constexpr_cookie, constexpr_group_dtls)    // dtls
                   << new payload_member(uint16(0), true, constexpr_cipher_suite_len) << new payload_member(binary_t(), constexpr_cipher_suite)
                   << new payload_member(uint8(0), constexpr_compression_method_len) << new payload_member(binary_t(), constexpr_compression_method)
                   << new payload_member(uint16(0), true, constexpr_extension_len);

                pl.set_group(constexpr_group_dtls, (record_version >= dtls_12));

                pl.select(constexpr_random)->reserve(32);
                pl.set_reference_value(constexpr_session_id, constexpr_session_id_len);
                pl.set_reference_value(constexpr_cipher_suite, constexpr_cipher_suite_len);
                pl.set_reference_value(constexpr_compression_method, constexpr_compression_method_len);
                pl.set_reference_value(constexpr_cookie, constexpr_cookie_len);  // dtls
                pl.read(stream, size, pos);

                // RFC 8446 4.1.1.  Cryptographic Negotiation
                // -  A list of cipher suites
                // -  A "supported_groups" (Section 4.2.7) extension
                // -  A "signature_algorithms" (Section 4.2.3) extension
                // -  A "pre_shared_key" (Section 4.2.11) extension

                version = pl.t_value_of<uint16>(constexpr_version);

                pl.get_binary(constexpr_random, random);
                session_id_len = pl.t_value_of<uint8>(constexpr_session_id_len);
                pl.get_binary(constexpr_session_id, session_id);
                cipher_suite_len = pl.t_value_of<uint16>(constexpr_cipher_suite_len);
                pl.get_binary(constexpr_cipher_suite, cipher_suite);
                compression_method_len = pl.t_value_of<uint8>(constexpr_compression_method_len);
                pl.get_binary(constexpr_compression_method, compression_method);
                extension_len = pl.t_value_of<uint16>(constexpr_extension_len);
            }

            if (debugstream) {
                debugstream->autoindent(1);
                debugstream->printf(" > %s 0x%04x (%s)\n", constexpr_version, version, tlsadvisor->tls_version_string(version).c_str());
                debugstream->printf(" > %s\n", constexpr_random);
                if (random.size()) {
                    // dump_memory(random, s, 16, 3, 0x0, dump_notrunc);
                    debugstream->printf("   %s\n", base16_encode(random).c_str());
                }
                debugstream->printf(" > %s %02x(%i)\n", constexpr_session_id, session_id_len, session_id_len);
                if (session_id.size()) {
                    debugstream->printf("   %s\n", base16_encode(session_id).c_str());
                }
                debugstream->printf(" > %s %i (%i entry)\n", constexpr_cipher_suite_len, cipher_suite_len, cipher_suite_len / sizeof(uint16));
                for (auto i = 0; i < cipher_suite_len / sizeof(uint16); i++) {
                    auto cs = t_binary_to_integer<uint16>(&cipher_suite[i << 1], sizeof(uint16));
                    debugstream->printf("   [%i] 0x%04x %s\n", i, cs, tlsadvisor->cipher_suite_string(cs).c_str());
                }
                debugstream->printf(" > %s %i\n", constexpr_compression_method_len, compression_method_len);
                for (auto i = 0; i < compression_method_len; i++) {
                    auto compr = t_binary_to_integer<uint8>(&compression_method[i], sizeof(uint8));
                    debugstream->printf("   [%i] 0x%02x %s\n", i, compr, tlsadvisor->compression_method_string(compr).c_str());
                }
                debugstream->printf(" > %s 0x%04x(%i)\n", constexpr_extension_len, extension_len, extension_len);
                debugstream->autoindent(0);
            }

            for (return_t test = errorcode_t::success;;) {
                test = tls_dump_extension(tls_hs_client_hello, session, stream, size, pos, debugstream);
                if (errorcode_t::no_more == test) {
                    break;
                } else if (errorcode_t::success == test) {
                    continue;
                } else {
                    ret = test;
                    break;
                }
            }

            // server_key_update
            protection.set_item(tls_context_client_hello_random, random);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
