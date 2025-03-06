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
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/string/string.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/extension/tls_extension.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_supported_versions.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_client_hello.hpp>
#include <sdk/net/tls/tls/record/tls_record_handshake.hpp>
#include <sdk/net/tls/tls/record/tls_records.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

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

tls_handshake_client_hello::tls_handshake_client_hello(tls_session* session) : tls_handshake(tls_hs_client_hello, session) {}

return_t tls_handshake_client_hello::do_preprocess(tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
        auto& protection = session->get_tls_protection();
        auto session_type = session->get_type();

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
                    keyexchange.erase(KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC);  // client_hello key_share
                    keyexchange.erase(KID_TLS_SERVERHELLO_KEYSHARE_PUBLIC);  // server_hello key_share
                } break;
                default: {
                } break;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_client_hello::do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
        auto& protection = session->get_tls_protection();

        // keycalc
        {
            auto hspos = offsetof_header();
            auto size_header_body = get_size();

            switch (protection.get_flow()) {
                case tls_1_rtt: {
                    // 1-RTT
                    protection.set_item(tls_context_client_hello, stream + hspos, size_header_body);  // transcript hash, see server_hello
                } break;
                case tls_0_rtt: {
                    protection.reset_transcript_hash(session);
                    protection.update_transcript_hash(session, stream + hspos, size_header_body /*, handshake_hash */);  // client_hello
                    ret = protection.calc(session, tls_hs_client_hello, dir);
                } break;
                case tls_hello_retry_request: {
                    protection.update_transcript_hash(session, stream + hspos, size_header_body /*, handshake_hash */);  // client_hello
                } break;
            }

            session->get_session_info(dir).set_status(get_type());
        }
        // protection_context
        auto& protection_context = protection.get_protection_context();
        {
            for (auto cs : _cipher_suites) {
                protection_context.add_cipher_suite(cs);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_client_hello::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
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

        auto& protection = session->get_tls_protection();

        {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

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

            uint16 legacy_version = protection.get_lagacy_version();
            uint16 version = 0;
            binary_t random;
            binary_t session_id;
            binary_t cipher_suites;
            binary_t compression_methods;
            uint8 session_id_len = 0;
            uint16 cipher_suite_len = 0;
            uint8 compression_method_len = 0;
            uint16 extension_len = 0;

            {
                payload pl;
                pl << new payload_member(uint16(0), true, constexpr_version)                    // TLS 1.2
                   << new payload_member(binary_t(), constexpr_random)                          // 32 bytes
                   << new payload_member(uint8(0), constexpr_session_id_len)                    //
                   << new payload_member(binary_t(), constexpr_session_id)                      //
                   << new payload_member(uint8(0), constexpr_cookie_len, constexpr_group_dtls)  // dtls
                   << new payload_member(binary_t(), constexpr_cookie, constexpr_group_dtls)    // dtls
                   << new payload_member(uint16(0), true, constexpr_cipher_suite_len)           //
                   << new payload_member(binary_t(), constexpr_cipher_suite)                    //
                   << new payload_member(uint8(0), constexpr_compression_method_len)            //
                   << new payload_member(binary_t(), constexpr_compression_method)              //
                   << new payload_member(uint16(0), true, constexpr_extension_len);             //

                pl.set_group(constexpr_group_dtls, is_kindof_dtls(legacy_version));

                pl.reserve(constexpr_random, 32);
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
                pl.get_binary(constexpr_cipher_suite, cipher_suites);
                compression_method_len = pl.t_value_of<uint8>(constexpr_compression_method_len);
                pl.get_binary(constexpr_compression_method, compression_methods);
                extension_len = pl.t_value_of<uint16>(constexpr_extension_len);
            }

            {
                for (auto i = 0; i < cipher_suite_len / sizeof(uint16); i++) {
                    auto cs = t_binary_to_integer<uint16>(&cipher_suites[i << 1], sizeof(uint16));
                    _cipher_suites.push_back(cs);
                }
                for (auto i = 0; i < compression_method_len; i++) {
                    auto compr = t_binary_to_integer<uint8>(&compression_methods[i], sizeof(uint8));
                    _compression_methods.push_back(compr);
                }
            }

            {
                _random = random;
                _session_id = session_id;
                set_extension_len(extension_len);
            }

            {
                // server_key_update
                protection.set_item(tls_context_client_hello_random, random);
            }

            if (istraceable()) {
                basic_stream dbs;
                tls_advisor* tlsadvisor = tls_advisor::get_instance();
                uint16 i = 0;

                dbs.autoindent(1);
                dbs.printf(" > %s 0x%04x (%s)\n", constexpr_version, version, tlsadvisor->tls_version_string(version).c_str());
                dbs.printf(" > %s\n", constexpr_random);
                if (random.size()) {
                    dbs.printf("   %s\n", base16_encode(random).c_str());
                }
                dbs.printf(" > %s %02x(%zi)\n", constexpr_session_id, session_id.size(), session_id.size());
                if (session_id.size()) {
                    dbs.printf("   %s\n", base16_encode(session_id).c_str());
                }
                dbs.printf(" > %s %04x(%i ent.)\n", constexpr_cipher_suite_len, cipher_suite_len, cipher_suite_len >> 1);
                i = 0;
                for (auto cs : _cipher_suites) {
                    dbs.printf("   [%i] 0x%04x %s\n", i++, cs, tlsadvisor->cipher_suite_string(cs).c_str());
                }
                dbs.printf(" > %s %i\n", constexpr_compression_method_len, compression_method_len);
                i = 0;
                for (auto compr : _compression_methods) {
                    dbs.printf("   [%i] 0x%02x %s\n", i++, compr, tlsadvisor->compression_method_string(compr).c_str());
                }
                dbs.printf(" > %s 0x%04x(%i)\n", constexpr_extension_len, extension_len, extension_len);
                dbs.autoindent(0);

                trace_debug_event(category_net, net_event_tls_read, &dbs);
            }

            ret = get_extensions().read(tls_hs_client_hello, session, dir, stream, size, pos);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_client_hello::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        auto& protection = session->get_tls_protection();

        binary_t extensions;
        get_extensions().write(extensions);

        {
            auto legacy_version = protection.get_lagacy_version();
            binary_t cipher_suites;
            for (uint16 cs : _cipher_suites) {
                binary_append(cipher_suites, cs, hton16);
            }

            binary_t compression_methods;
            compression_methods.resize(1);

            if (32 != _random.size()) {
                _random.get().resize(32);
            }

            payload pl;
            pl << new payload_member(uint16(legacy_version), true, constexpr_version)                      //
               << new payload_member(_random, constexpr_random)                                            //
               << new payload_member(uint8(_session_id.size()), constexpr_session_id_len)                  //
               << new payload_member(_session_id, constexpr_session_id)                                    //
               << new payload_member(uint8(0), constexpr_cookie_len, constexpr_group_dtls)                 // dtls
               << new payload_member(binary_t(), constexpr_cookie, constexpr_group_dtls)                   // dtls
               << new payload_member(uint16(cipher_suites.size()), true, constexpr_cipher_suite_len)       //
               << new payload_member(cipher_suites, constexpr_cipher_suite)                                //
               << new payload_member(uint8(compression_methods.size()), constexpr_compression_method_len)  //
               << new payload_member(compression_methods, constexpr_compression_method)                    //
               << new payload_member(uint16(extensions.size()), true, constexpr_extension_len);            //

            pl.set_group(constexpr_group_dtls, is_kindof_dtls(legacy_version));
            pl.write(bin);
        }

        { protection.set_item(tls_context_client_hello_random, _random); }

        binary_append(bin, extensions);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void tls_handshake_client_hello::set_random(const binary_t& value) { _random = value; }

void tls_handshake_client_hello::set_session_id(const binary_t& value) { _session_id = value; }

const binary& tls_handshake_client_hello::get_random() { return _random; }

const binary& tls_handshake_client_hello::get_session_id() { return _session_id; }

const std::vector<uint16>& tls_handshake_client_hello::get_cipher_suites() { return _cipher_suites; }

const std::vector<uint8>& tls_handshake_client_hello::get_compression_methods() { return _compression_methods; }

return_t tls_handshake_client_hello::add_ciphersuites(const char* ciphersuites) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == ciphersuites) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto lambda = [&](const std::string& item) -> void {
            auto hint = tlsadvisor->hintof_cipher_suite(item);
            if (hint && hint->support) {
                auto code = hint->code;
                _cipher_suites.push_back(code);
            }
        };

        split_context_t* context = nullptr;
        split_begin(&context, ciphersuites, ":");
        split_foreach(context, lambda);
        split_end(context);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_client_hello::add_ciphersuite(uint16 ciphersuite) {
    return_t ret = errorcode_t::success;
    _cipher_suites.push_back(ciphersuite);
    return ret;
}

tls_handshake_client_hello& tls_handshake_client_hello::operator<<(const std::string& ciphersuites) {
    add_ciphersuites(ciphersuites.c_str());
    return *this;
}

}  // namespace net
}  // namespace hotplace
