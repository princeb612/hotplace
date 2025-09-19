/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_hmac.hpp>
#include <hotplace/sdk/crypto/basic/openssl_kdf.hpp>
#include <hotplace/sdk/crypto/basic/transcript_hash.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_finished.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

/**
 * TLS 1.2 PRF(master_secret, label, hash(handshake_message))
 *         master_secret after keyexchange
 * TLS 1.3 HMAC(finished_key, hash(handshake context))
 */

constexpr char constexpr_verify_data[] = "verify data";

tls_handshake_finished::tls_handshake_finished(tls_session* session) : tls_handshake(tls_hs_finished, session) {}

tls_handshake_finished::~tls_handshake_finished() {}

void tls_handshake_finished::run_scheduled(tls_direction_t dir) {
    auto session = get_session();
    auto& session_info = session->get_session_info(dir);
    session_info.set_status(get_type());
    session->reset_recordno(dir);
}

return_t tls_handshake_finished::do_preprocess(tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    __try2 {
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        auto tlsver = protection.get_tls_version();
        auto session_status = session->get_session_status();
        uint32 session_status_prerequisite = 0;
        auto flow = protection.get_flow();
        if (true == tlsadvisor->is_kindof_tls13(tlsver)) {
            if (tls_flow_1rtt == flow) {
                // RFC 8446 5.  Record Protocol
                //  The change_cipher_spec record is used only for compatibility purposes.
                // RFC 8448 3.  Simple 1-RTT Handshake

                // certificate, certificate_verify, finished(server), finished(client)
                session_status_prerequisite = session_status_server_cert_verified;
                if (from_client == dir) {
                    session_status_prerequisite != session_status_server_finished;
                }
            } else if (tls_flow_0rtt == flow) {
                session_status_prerequisite = session_status_client_hello | session_status_server_hello | session_status_encrypted_extensions;
            }
        } else {
            // TLS 1.2, DTLS 1.2
            // change_cipher_spec
            bool isprotected = session->get_session_info(dir).apply_protection();
            if (false == isprotected) {
                ret = errorcode_t::confidential;
                __leave2;
            }

            // certificate, server_key_exchange, server_hello_done, client_key_exchange
            // change_cipher_spec(client), finished(client), change_cipher_spec(server), finished(server)
            session_status_prerequisite = session_status_server_key_exchange | session_status_client_key_exchange;
            if (from_server == dir) {
                session_status_prerequisite |= session_status_client_finished;
            }
        }

        if (session_status_prerequisite != (session_status_prerequisite & session_status)) {
            session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_unexpected_message);
            session->reset_session_status();
            ret = errorcode_t::error_handshake;
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_finished::do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto hspos = offsetof_header();
        auto& protection = session->get_tls_protection();
        auto& secrets = protection.get_secrets();

        {
            protection.update_transcript_hash(session, stream + hspos, get_size());

            // from_server : application, exporter related
            // from_client : resumption related
            protection.calc(session, tls_hs_finished, dir);

            secrets.erase(tls_context_client_hello_random);
            secrets.erase(tls_context_server_hello_random);

            session->get_keyvalue().set(session_handshake_finished, 1);

            if (from_client == dir) {
                secrets.assign(tls_context_client_verifydata, _verify_data);
            } else if (from_server == dir) {
                secrets.assign(tls_context_server_verifydata, _verify_data);
            }

            if (from_server == dir) {
                session->update_session_status(session_status_server_finished);
            } else if (from_client == dir) {
                session->update_session_status(session_status_client_finished);
            }
            session->schedule(this);  // run_scheduled
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_finished::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // RFC 8446 2.  Protocol Overview
        // Finished:  A MAC (Message Authentication Code) over the entire
        //    handshake.  This message provides key confirmation, binds the
        //    endpoint's identity to the exchanged keys, and in PSK mode also
        //    authenticates the handshake.  [Section 4.4.4]

        crypto_advisor* advisor = crypto_advisor::get_instance();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        auto& secrets = protection.get_secrets();
        auto tlsversion = protection.get_tls_version();
        uint16 dlen = 0;
        hash_algorithm_t hmacalg;
        {
            const tls_cipher_suite_t* hint_tls_alg = tlsadvisor->hintof_cipher_suite(protection.get_cipher_suite());
            if (nullptr == hint_tls_alg) {
                ret = errorcode_t::not_supported;
                __leave2;
            }
            if (tlsadvisor->is_kindof_tls13(tlsversion)) {
                dlen = sizeof_digest(advisor->hintof_digest(hint_tls_alg->mac));
            } else {
                dlen = 12;
            }
            hmacalg = algof_mac(hint_tls_alg);
        }

        binary_t verify_data;

        {
            payload pl;
            pl << new payload_member(binary_t(), constexpr_verify_data);
            pl.reserve(constexpr_verify_data, dlen);
            pl.read(stream, size, pos);

            pl.get_binary(constexpr_verify_data, verify_data);
        }

        {
            tls_secret_t typeof_secret;
            binary_t maced;
            protection.calc_finished(dir, hmacalg, dlen, typeof_secret, maced);

            verify_data.resize(maced.size());
            if (maced.empty() || (verify_data != maced)) {
                session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_handshake_failure);
                session->reset_session_status();
                ret = errorcode_t::error_verify;
            }

#if defined DEBUG
            if (istraceable(trace_category_net)) {
                basic_stream dbs;
                dbs.autoindent(1);
                dbs.println("> %s \e[1;33m%s\e[0m", constexpr_verify_data, (errorcode_t::success == ret) ? "true" : "false");
                if (check_trace_level(loglevel_debug)) {
                    dump_memory(verify_data, &dbs, 16, 3, 0x00, dump_notrunc);
                }
                const binary_t ht_secret = secrets.get(typeof_secret);
                dbs.println("  > secret [0x%08x] %s (%s)", typeof_secret, base16_encode(ht_secret).c_str(), tlsadvisor->nameof_secret(typeof_secret).c_str());
                dbs.println("  > algorithm %s size %i", advisor->nameof_md(hmacalg), dlen);
                dbs.println("  > verify data %s", base16_encode(verify_data).c_str());
                dbs.println("  > maced       %s", base16_encode(maced).c_str());
                dbs.autoindent(0);

                trace_debug_event(trace_category_net, trace_event_tls_handshake, &dbs);
            }
#endif

            if (errorcode_t::success != ret) {
                __leave2;
            }

            _verify_data = std::move(verify_data);
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_finished::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        auto& secrets = protection.get_secrets();

        crypto_advisor* advisor = crypto_advisor::get_instance();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto tlsversion = protection.get_tls_version();
        uint16 dlen = 0;
        hash_algorithm_t hmacalg;
        {
            const tls_cipher_suite_t* hint_tls_alg = tlsadvisor->hintof_cipher_suite(protection.get_cipher_suite());
            if (nullptr == hint_tls_alg) {
                ret = errorcode_t::success;
                __leave2;
            }
            if (tlsadvisor->is_kindof_tls13(tlsversion)) {
                dlen = sizeof_digest(advisor->hintof_digest(hint_tls_alg->mac));
            } else {
                dlen = 12;
            }
            hmacalg = algof_mac(hint_tls_alg);
        }

        tls_secret_t typeof_secret;
        binary_t verify_data;
        protection.calc_finished(dir, hmacalg, dlen, typeof_secret, verify_data);

        {
            payload pl;
            pl << new payload_member(verify_data, constexpr_verify_data);
            pl.write(bin);
        }

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println("> %s", constexpr_verify_data);
            if (check_trace_level(loglevel_debug)) {
                dump_memory(verify_data, &dbs, 16, 3, 0x00, dump_notrunc);
            }
            const binary_t ht_secret = secrets.get(typeof_secret);
            dbs.println("  > secret [0x%08x] %s (%s)", typeof_secret, base16_encode(ht_secret).c_str(), tlsadvisor->nameof_secret(typeof_secret).c_str());
            dbs.println("  > algorithm %s size %i", advisor->nameof_md(hmacalg), dlen);
            dbs.println("  > verify data %s", base16_encode(verify_data).c_str());

            trace_debug_event(trace_category_net, trace_event_tls_handshake, &dbs);
        }
#endif

        _verify_data = std::move(verify_data);
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
