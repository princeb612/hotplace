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
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/extension/tls_extension.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_server_hello.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_version[] = "version";
constexpr char constexpr_random[] = "random";
constexpr char constexpr_session_id_len[] = "session id len";
constexpr char constexpr_session_id[] = "session id";
constexpr char constexpr_cipher_suite[] = "cipher suite";
constexpr char constexpr_compression_method[] = "compression method";
constexpr char constexpr_extension_len[] = "extension len";
constexpr char constexpr_extension[] = "extension";

constexpr char constexpr_group_dtls[] = "dtls";
constexpr char constexpr_cookie_len[] = "cookie len";
constexpr char constexpr_cookie[] = "cookie";

tls_handshake_server_hello::tls_handshake_server_hello(tls_session* session)
    : tls_handshake(tls_hs_server_hello, session), _version(0), _compression_method(0) {}

void tls_handshake_server_hello::set_version(uint16 version) { _version = version; }

void tls_handshake_server_hello::set_random(const binary_t& value) { _random = value; }

void tls_handshake_server_hello::set_session_id(const binary_t& value) { _session_id = value; }

uint16 tls_handshake_server_hello::get_version() { return _version; }

const binary& tls_handshake_server_hello::get_random() { return _random; }

const binary& tls_handshake_server_hello::get_session_id() { return _session_id; }

uint16 tls_handshake_server_hello::get_cipher_suite() {
    uint16 cs = 0;
    auto session = get_session();
    if (session) {
        auto& protection = session->get_tls_protection();
        cs = protection.get_cipher_suite();
    }
    return cs;
}

return_t tls_handshake_server_hello::set_cipher_suite(uint16 cs) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto hint = tlsadvisor->hintof_cipher_suite(cs);
        if (nullptr == hint) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (false == hint->support) {
            auto test = session->get_keyvalue().get(session_debug_deprecated_ciphersuite);
            if (0 == test) {
                ret = errorcode_t::bad_request;
                __leave2;
            }
        }

        auto& protection = session->get_tls_protection();
        protection.set_cipher_suite(cs);
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_server_hello::set_cipher_suite(const char* cs) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cs) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto hint = tlsadvisor->hintof_cipher_suite(cs);
        if (nullptr == hint) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (false == hint->support) {
            auto test = session->get_keyvalue().get(session_debug_deprecated_ciphersuite);
            if (0 == test) {
                ret = errorcode_t::bad_request;
                __leave2;
            }
        }

        auto& protection = session->get_tls_protection();
        protection.set_cipher_suite(hint->code);
    }
    __finally2 {}
    return ret;
}

uint8 tls_handshake_server_hello::get_compression_method() { return _compression_method; }

return_t tls_handshake_server_hello::do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        auto hspos = offsetof_header();
        auto size_header_body = get_size();
        auto& protection = session->get_tls_protection();
        auto session_type = session->get_type();

        {
            // calculates the hash of all handshake messages to this point (ClientHello and ServerHello).
            binary_t hello_hash;
            if (tls_1_rtt == protection.get_flow()) {
                const binary_t& client_hello = protection.get_item(tls_context_client_hello);
                protection.update_transcript_hash(session, &client_hello[0], client_hello.size());  // client_hello
            }

            protection.calc_transcript_hash(session, stream + hspos, size_header_body, hello_hash);  // server_hello
            auto test = protection.calc(session, tls_hs_server_hello, dir);
            auto& session_info = session->get_session_info(dir);
            session_info.set_status(get_type());
            session->get_session_info(from_client).set_status(get_type());
            if (errorcode_t::warn_retry == test) {
                // if warn_retry, do HRR
                protection.set_flow(tls_hello_retry_request);

                /**
                 *    RFC 8446 4.4.1.  The Transcript Hash
                 *
                 *       As an exception to this general rule, when the server responds to a
                 *       ClientHello with a HelloRetryRequest, the value of ClientHello1 is
                 *       replaced with a special synthetic handshake message of handshake type
                 *       "message_hash" containing Hash(ClientHello1).  I.e.,
                 *
                 *       Transcript-Hash(ClientHello1, HelloRetryRequest, ... Mn) =
                 *           Hash(message_hash ||        // Handshake type
                 *                00 00 Hash.length  ||  // Handshake message length (bytes)
                 *                Hash(ClientHello1) ||  // Hash of ClientHello1
                 *                HelloRetryRequest  || ... || Mn)
                 */
                binary_t handshake_hash;
                const binary_t& client_hello = protection.get_item(tls_context_client_hello);
                protection.reset_transcript_hash(session);
                protection.calc_transcript_hash(session, &client_hello[0], client_hello.size(), handshake_hash);

                binary message_hash;
                message_hash << uint8(tls_hs_message_hash) << uint16(0) << byte_t(handshake_hash.size()) << handshake_hash;
                const binary_t& synthetic_handshake_message = message_hash.get();

                protection.reset_transcript_hash(session);
                protection.update_transcript_hash(session, &synthetic_handshake_message[0], synthetic_handshake_message.size());
                protection.calc_transcript_hash(session, stream + hspos, size_header_body, hello_hash);
            } else {
                ret = test;
            }

            protection.clear_item(tls_context_client_hello);
        }
        if ((session_quic == session_type) || (session_quic2 == session_type)) {
            session->reset_recordno(from_server);
        }

        auto ext = get_extensions().get(tls1_ext_supported_versions);
        if (nullptr == ext) {
            auto legacy_version = protection.get_lagacy_version();
            protection.set_tls_version(_version ? _version : legacy_version);
        }

        session->update_session_status(session_server_hello);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_server_hello::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
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

            /* RFC 8446 4.1.3.  Server Hello */

            auto& protection = session->get_tls_protection();
            uint16 legacy_version = protection.get_lagacy_version();
            uint16 version = 0;

            binary_t random;
            binary_t session_id;
            uint8 session_ids = 0;
            uint16 cipher_suite = 0;
            uint8 compression_method = 0;
            uint8 extension_len = 0;

            binary_t bin_server_hello;

            {
                payload pl;
                pl << new payload_member(uint16(0), true, constexpr_version)         //
                   << new payload_member(binary_t(), constexpr_random)               //
                   << new payload_member(uint8(0), constexpr_session_id_len)         //
                   << new payload_member(binary_t(), constexpr_session_id)           //
                   << new payload_member(uint16(0), true, constexpr_cipher_suite)    //
                   << new payload_member(uint8(0), constexpr_compression_method)     //
                   << new payload_member(uint16(0), true, constexpr_extension_len);  //

                pl.set_group(constexpr_group_dtls, is_kindof_dtls(legacy_version));

                pl.reserve(constexpr_random, 32);
                pl.set_reference_value(constexpr_session_id, constexpr_session_id_len);
                pl.read(stream, size, pos);

                // RFC 8446 4.1.1.  Cryptographic Negotiation
                // If PSK is being used, ... "pre_shared_key" extension indicating the selected key
                // When (EC)DHE is in use, ... "key_share" extension
                // When authenticating via a certificate, ... Certificate (Section 4.4.2) and CertificateVerify (Section 4.4.3)

                version = pl.t_value_of<uint16>(constexpr_version);

                pl.get_binary(constexpr_random, random);
                session_ids = pl.t_value_of<uint8>(constexpr_session_id_len);
                pl.get_binary(constexpr_session_id, session_id);
                cipher_suite = pl.t_value_of<uint16>(constexpr_cipher_suite);
                compression_method = pl.t_value_of<uint8>(constexpr_compression_method);
                extension_len = pl.t_value_of<uint16>(constexpr_extension_len);
            }

#if defined DEBUG
            if (istraceable()) {
                basic_stream dbs;
                dbs.autoindent(1);
                dbs.println(" > %s 0x%04x (%s)", constexpr_version, version, tlsadvisor->tls_version_string(version).c_str());
                dbs.println(" > %s", constexpr_random);
                if (random.size()) {
                    // dump_memory(random, s, 16, 3, 0x0, dump_notrunc);
                    dbs.println("   %s", base16_encode(random).c_str());
                }
                dbs.println(" > %s", constexpr_session_id);
                if (session_id.size()) {
                    dbs.println("   %s", base16_encode(session_id).c_str());
                }
                dbs.println(" > %s 0x%04x %s", constexpr_cipher_suite, cipher_suite, tlsadvisor->cipher_suite_string(cipher_suite).c_str());
                dbs.println(" > %s %i %s", constexpr_compression_method, compression_method, tlsadvisor->compression_method_string(compression_method).c_str());
                dbs.println(" > %s 0x%02x(%i)", constexpr_extension_len, extension_len, extension_len);
                dbs.autoindent(0);

                trace_debug_event(trace_category_net, trace_event_tls_handshake, &dbs);
            }
#endif

            ret = get_extensions().read(tls_hs_server_hello, session, dir, stream, size, pos);

            // cipher_suite
            set_cipher_suite(cipher_suite);

            // server_key_update
            session->get_tls_protection().set_item(tls_context_server_hello_random, random);

            _version = version;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_server_hello::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();

        auto legacy_version = session->get_tls_protection().get_lagacy_version();

        binary_t extensions;
        get_extensions().write(extensions);

        {
            payload pl;
            pl << new payload_member(uint16(_version ? _version : legacy_version), true, constexpr_version)  //
               << new payload_member(_random, constexpr_random)                                              //
               << new payload_member(uint8(_session_id.size()), constexpr_session_id_len)                    //
               << new payload_member(_session_id, constexpr_session_id)                                      //
               << new payload_member(uint16(get_cipher_suite()), true, constexpr_cipher_suite)               //
               << new payload_member(uint8(0), constexpr_compression_method)                                 //
               << new payload_member(uint16(extensions.size()), true, constexpr_extension_len);              //

            pl.set_group(constexpr_group_dtls, is_kindof_dtls(legacy_version));
            pl.write(bin);
        }

        { session->get_tls_protection().set_item(tls_context_server_hello_random, _random); }

        binary_append(bin, extensions);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
