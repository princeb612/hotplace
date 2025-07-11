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
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/extension/tls_extension.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_renegotiation_info.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_supported_groups.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_unknown.hpp>
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
    auto& protection = session->get_tls_protection();
    cs = protection.get_cipher_suite();
    return cs;
}

return_t tls_handshake_server_hello::set_cipher_suite(uint16 cs) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto hint = tlsadvisor->hintof_cipher_suite(cs);
        if (nullptr == hint) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (0 == (tls_flag_support & hint->flags)) {
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
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto hint = tlsadvisor->hintof_cipher_suite(cs);
        if (nullptr == hint) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (0 == (tls_flag_support & hint->flags)) {
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

return_t tls_handshake_server_hello::do_preprocess(tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (from_server != dir) {
            ret = errorcode_t::bad_request;
            __leave2;
        }

        auto session = get_session();
        auto session_status = session->get_session_status();
        if (0 == (session_status_client_hello & session_status)) {
            session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_unexpected_message);
            session->reset_session_status();
            ret = errorcode_t::error_handshake;
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_server_hello::do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        auto& secrets = protection.get_secrets();
        auto& kv = session->get_keyvalue();
        auto session_type = session->get_type();
        auto hspos = offsetof_header();
        auto size_header_body = get_size();

        {
            auto ext_version = get_extensions().get(tls_ext_supported_versions);
            if (nullptr == ext_version) {
                // TLS 1.2
                auto legacy_version = protection.get_lagacy_version();
                protection.set_tls_version(_version ? _version : legacy_version);
            } else {
                // TLS 1.3 supported_versions extension
                // read/write member calls protection.set_tls_version
            }
        }

        {
            // calculates the hash of all handshake messages to this point (ClientHello and ServerHello).
            binary_t hello_hash;
            switch (protection.get_flow()) {
                case tls_flow_1rtt: {
                    protection.reset_transcript_hash(session);

                    const binary_t& client_hello = secrets.get(tls_context_client_hello);
                    protection.update_transcript_hash(session, &client_hello[0], client_hello.size());  // client_hello
                } break;
                case tls_flow_0rtt:
                case tls_flow_hello_retry_request: {
                    auto hs_finished = kv.get(session_handshake_finished);
                    if (hs_finished) {
                        protection.set_flow(tls_flow_0rtt);
                    } else {
                        protection.set_flow(tls_flow_1rtt);
                    }

                    auto session_version = kv.get(session_tls_version);
                    auto version = protection.get_tls_version();

                    bool downgrade = (session_type_dtls == session_type) ? (session_version < version) : (session_version > version);
                    if (downgrade) {
                        session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_protocol_version);
                        session->reset_session_status();
                        ret = errorcode_t::error_handshake;
                    }
                } break;
            }
            if (errorcode_t::success != ret) {
                __leave2;
            }

            protection.calc_transcript_hash(session, stream + hspos, size_header_body, hello_hash);  // server_hello

            auto test = protection.calc(session, tls_hs_server_hello, dir);
            auto& session_info = session->get_session_info(dir);
            session_info.set_status(get_type());
            session->get_session_info(from_client).set_status(get_type());
            if (errorcode_t::warn_retry == test) {
                // if warn_retry, do HRR

                // RFC 8446 2.1
                // If the client has not provided a sufficient "key_share" extension, the server corrects the mismatch with a
                // HelloRetryRequest and the client needs to restart the handshake with an appropriate "key_share" extension.

                protection.set_flow(tls_flow_hello_retry_request);
                session->clear_session_status(session_status_client_hello);

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

                protection.reset_transcript_hash(session);

                // client_hello
                const binary_t& client_hello = secrets.get(tls_context_client_hello);
                protection.calc_transcript_hash(session, &client_hello[0], client_hello.size(), handshake_hash);

                // uint8(FE) || uint24(hash.size) || hash
                binary message_hash;
                message_hash << uint8(tls_hs_message_hash) << uint16(0) << byte_t(handshake_hash.size()) << handshake_hash;
                const binary_t& synthetic_handshake_message = message_hash.get();

                protection.reset_transcript_hash(session);

                protection.update_transcript_hash(session, &synthetic_handshake_message[0], synthetic_handshake_message.size());

                // server_hello
                protection.calc_transcript_hash(session, stream + hspos, size_header_body, hello_hash);

                secrets.erase(tls_context_client_hello);
            } else {
                ret = test;
            }
        }
        if ((session_type_quic == session_type) || (session_type_quic2 == session_type)) {
            session->reset_recordno(from_server);
        }

        kv.set(session_tls_version, protection.get_tls_version());
        session->update_session_status(session_status_server_hello);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_server_hello::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        {
            /* RFC 8446 4.1.3.  Server Hello */

            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            auto session = get_session();
            auto& protection = session->get_tls_protection();
            auto& secrets = protection.get_secrets();
            auto& kv = session->get_keyvalue();
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

                pl.set_group(constexpr_group_dtls, tlsadvisor->is_kindof_dtls(legacy_version));

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

            if (0 == extension_len) {
                session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_missing_extension);
                session->reset_session_status();
                ret = errorcode_t::error_handshake;
                __leave2;
            }

#if defined DEBUG
            if (istraceable(trace_category_net)) {
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

            ret = get_extensions().read(this, dir, stream, pos + extension_len, pos);

            // encrypt_then_mac
            {
                auto request_etm = kv.get(session_encrypt_then_mac);
                auto ext_etm = get_extensions().get(tls_ext_encrypt_then_mac);
                if (request_etm) {
                    // client_hello.get_extensions.has(etm extension) && server_hello.get_extensions.has(etm extension)
                    session->get_keyvalue().set(session_encrypt_then_mac, (request_etm && ext_etm) ? 1 : 0);
                } else {
                    if (ext_etm) {
                        session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_handshake_failure);
                        session->reset_session_status();
                        ret = error_handshake;
                        __leave2;
                    }
                }
            }
            // extended master secret
            {
                auto request_ems = kv.get(session_extended_master_secret);
                auto ext_ems = get_extensions().get(tls_ext_extended_master_secret);
                if (request_ems) {
                    // client_hello.get_extensions.has(ems extension) && server_hello.get_extensions.has(ems extension)
                    session->get_keyvalue().set(session_extended_master_secret, (request_ems && ext_ems) ? 1 : 0);
                } else {
                    if (ext_ems) {
                        session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_handshake_failure);
                        session->reset_session_status();
                        ret = error_handshake;
                        __leave2;
                    }
                }
            }

            // cipher_suite
            set_cipher_suite(cipher_suite);

            // server_key_update
            secrets.assign(tls_context_server_hello_random, random);

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
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        auto& secrets = protection.get_secrets();
        auto& kv = session->get_keyvalue();
        auto legacy_version = protection.get_lagacy_version();
        auto cs = get_cipher_suite();
        auto hint = tlsadvisor->hintof_cipher_suite(cs);

        {
            // encrypt_then_mac
            auto request_etm = kv.get(session_encrypt_then_mac);
            if (request_etm) {
                if (tlsadvisor->is_kindof_cbc(cs)) {
                    auto ext_etm = get_extensions().get(tls_ext_encrypt_then_mac);
                    if (nullptr == ext_etm) {
                        get_extensions().add(new tls_extension_unknown(tls_ext_encrypt_then_mac, this));
                    }
                }
            }
            auto ext_etm = get_extensions().get(tls_ext_encrypt_then_mac);
            // test session_conf_etm && client_hello.get_extensions.has(etm extension) && server_hello.get_extensions.has(etm extension)
            session->get_keyvalue().set(session_encrypt_then_mac, (request_etm && ext_etm) ? 1 : 0);
        }
        {
            // extended master secret
            auto request_ems = kv.get(session_extended_master_secret);
            if (tls_12 == hint->version) {
                if (request_ems) {
                    auto ext_ems = get_extensions().get(tls_ext_extended_master_secret);
                    if (nullptr == ext_ems) {
                        get_extensions().add(new tls_extension_unknown(tls_ext_extended_master_secret, this));
                    }
                }
            }
            auto ext_ems = get_extensions().get(tls_ext_extended_master_secret);
            // test session_conf_ems && client_hello.get_extensions.has(ems extension) && server_hello.get_extensions.has(ems extension)
            session->get_keyvalue().set(session_extended_master_secret, (request_ems && ext_ems) ? 1 : 0);
        }
        if (tls_12 == hint->version) {
            // fatal:handshake_failure
            // avoid final_renegotiate:unsafe legacy renegotiation disabled
            auto ext_renego = get_extensions().get(tls_ext_renegotiation_info);
            if (nullptr == ext_renego) {
                auto renegotiation_info = new tls_extension_renegotiation_info(this);
                get_extensions().add(renegotiation_info);
            }

            // TLS 1.2 server_hello
            // TLS 1.3 encrypted_extensions
            session->select_into_scheduled_extension(&get_extensions(), tls_ext_alpn);
        }

        binary_t extensions;
        ret = get_extensions().write(dir, extensions);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // RFC 8446
        // If there is no overlap between the received "supported_groups" and the groups supported by the server, then the
        // server MUST abort the handshake with a "handshake_failure" or an "insufficient_security" alert.
        auto ext_sg = get_extensions().get(tls_ext_supported_groups);
        if (ext_sg) {
            tls_extension_supported_groups* ext_sg_casted = (tls_extension_supported_groups*)ext_sg;
            if (0 == ext_sg_casted->numberof_groups()) {
                session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_handshake_failure);
                session->reset_session_status();
                ret = errorcode_t::error_handshake;
                __leave2;
            }
        }

        if (32 != _random.size()) {
            // gmt_unix_time(4 bytes) + random(28 bytes)
            openssl_prng prng;
            binary_t random;
            time_t gmt_unix_time = time(nullptr);
            uint32 gmt = (uint32)gmt_unix_time;
            binary_append(random, gmt, hton32);
            binary_t temp;
            prng.random(temp, 28);
            binary_append(random, temp);

            _random = std::move(random);

            _session_id = secrets.get(tls_context_session_id);  // avoid routines:tls_process_server_hello:invalid session id
        }

        {
            payload pl;
            pl << new payload_member(uint16(_version ? _version : legacy_version), true, constexpr_version)  //
               << new payload_member(_random, constexpr_random)                                              //
               << new payload_member(uint8(_session_id.size()), constexpr_session_id_len)                    //
               << new payload_member(_session_id, constexpr_session_id)                                      //
               << new payload_member(uint16(cs), true, constexpr_cipher_suite)                               //
               << new payload_member(uint8(0), constexpr_compression_method)                                 //
               << new payload_member(uint16(extensions.size()), true, constexpr_extension_len);              //

            pl.set_group(constexpr_group_dtls, tlsadvisor->is_kindof_dtls(legacy_version));
            pl.write(bin);
        }

        secrets.assign(tls_context_server_hello_random, _random);

        binary_append(bin, extensions);

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println("> encrypt_then_mac %i", kv.get(session_encrypt_then_mac) ? 1 : 0);
            dbs.println("> extended master secret %i", kv.get(session_extended_master_secret));
            trace_debug_event(trace_category_net, trace_event_tls_handshake, &dbs);
        }
#endif
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
