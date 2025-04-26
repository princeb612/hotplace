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
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_hmac.hpp>
#include <sdk/crypto/basic/openssl_kdf.hpp>
#include <sdk/crypto/basic/transcript_hash.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_finished.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

/**
 * TLS 1.2 PRF(master_secret, label, hash(handshake_message))
 *         master_secret after keyexchange
 * TLS 1.3 HMAC(finished_key, hash(handshake context))
 */

constexpr char constexpr_verify_data[] = "verify data";

tls_handshake_finished::tls_handshake_finished(tls_session* session) : tls_handshake(tls_hs_finished, session) {}

void tls_handshake_finished::run_scheduled(tls_direction_t dir) {
    auto session = get_session();
    auto& session_info = session->get_session_info(dir);
    session_info.set_status(get_type());
    session->reset_recordno(dir);
}

return_t tls_handshake_finished::do_preprocess(tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    auto session = get_session();
    auto tlsver = session->get_tls_protection().get_tls_version();
    if (true == tlsadvisor->is_kindof_tls13(tlsver)) {
        // RFC 8446 5.  Record Protocol
        //  The change_cipher_spec record is used only for compatibility purposes.
        // RFC 8448 3.  Simple 1-RTT Handshake
    } else {
        // TLS 1.2, DTLS 1.2
        bool isprotected = session->get_session_info(dir).apply_protection();
        if (false == isprotected) {
            ret = errorcode_t::confidential;
        }
    }
    return ret;
}

return_t tls_handshake_finished::do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
        auto hspos = offsetof_header();
        auto& protection = session->get_tls_protection();

        {
            protection.update_transcript_hash(session, stream + hspos, get_size());

            // from_server : application, exporter related
            // from_client : resumption related
            protection.calc(session, tls_hs_finished, dir);

            if (from_server == dir) {
                session->update_session_status(session_server_finished);
            } else if (from_client == dir) {
                session->update_session_status(session_client_finished);
            }

            session->schedule(this);  // run_scheduled
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_finished::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session = get_session();
        auto& protection = session->get_tls_protection();

        // RFC 8446 2.  Protocol Overview
        // Finished:  A MAC (Message Authentication Code) over the entire
        //    handshake.  This message provides key confirmation, binds the
        //    endpoint's identity to the exchanged keys, and in PSK mode also
        //    authenticates the handshake.  [Section 4.4.4]

        crypto_advisor* advisor = crypto_advisor::get_instance();
        auto tlsversion = protection.get_tls_version();
        uint16 dlen = 0;
        hash_algorithm_t hmacalg;
        {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
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
            if (verify_data != maced) {
                ret = errorcode_t::error_verify;
            }

#if defined DEBUG
            if (istraceable()) {
                basic_stream dbs;
                dbs.autoindent(1);
                dbs.println("> %s \e[1;33m%s\e[0m", constexpr_verify_data, (errorcode_t::success == ret) ? "true" : "false");
                dump_memory(verify_data, &dbs, 16, 3, 0x00, dump_notrunc);
                dbs.println("  > secret (internal) 0x%08x", typeof_secret);
                dbs.println("  > algorithm %s size %i", advisor->nameof_md(hmacalg), dlen);
                dbs.println("  > verify data %s", base16_encode(verify_data).c_str());
                dbs.println("  > maced       %s", base16_encode(maced).c_str());
                dbs.autoindent(0);

                trace_debug_event(trace_category_net, trace_event_tls_handshake, &dbs);
            }
#endif
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_finished::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();

        crypto_advisor* advisor = crypto_advisor::get_instance();
        auto tlsversion = protection.get_tls_version();
        uint16 dlen = 0;
        hash_algorithm_t hmacalg;
        {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
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
        { protection.calc_finished(dir, hmacalg, dlen, typeof_secret, verify_data); }

        {
            payload pl;
            pl << new payload_member(verify_data, constexpr_verify_data);
            pl.write(bin);
        }

#if defined DEBUG
        if (istraceable()) {
            basic_stream dbs;
            dbs.println("> %s", constexpr_verify_data);
            dump_memory(verify_data, &dbs, 16, 3, 0x00, dump_notrunc);
            dbs.println("  > secret (internal) 0x%08x", typeof_secret);
            dbs.println("  > algorithm %s size %i", advisor->nameof_md(hmacalg), dlen);
            dbs.println("  > verify data %s", base16_encode(verify_data).c_str());

            trace_debug_event(trace_category_net, trace_event_tls_handshake, &dbs);
        }
#endif
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
