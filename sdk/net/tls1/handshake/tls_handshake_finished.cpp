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
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/openssl_kdf.hpp>
#include <sdk/crypto/crypto/crypto_hmac.hpp>
#include <sdk/crypto/crypto/transcript_hash.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls1/handshake/tls_handshake_finished.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

tls_handshake_finished::tls_handshake_finished(tls_session* session) : tls_handshake(tls_hs_finished, session) {}

return_t tls_handshake_finished::do_handshake(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
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
            // RFC 8446 2.  Protocol Overview
            // Finished:  A MAC (Message Authentication Code) over the entire
            //    handshake.  This message provides key confirmation, binds the
            //    endpoint's identity to the exchanged keys, and in PSK mode also
            //    authenticates the handshake.  [Section 4.4.4]

            ret = do_read(dir, stream, size, pos, debugstream);

            protection.calc_transcript_hash(session, stream + hspos, hdrsize);

            // from_server : application, exporter related
            // from_client : resumption related
            protection.calc(session, tls_hs_finished, dir);

            session->get_session_info(dir).set_status(get_type());

            session->reset_recordno(dir);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_finished::do_read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
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
            auto& protection = session->get_tls_protection();
            crypto_advisor* advisor = crypto_advisor::get_instance();
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            const tls_cipher_suite_t* hint_tls_alg = tlsadvisor->hintof_cipher_suite(protection.get_cipher_suite());
            if (nullptr == hint_tls_alg) {
                ret = errorcode_t::not_supported;
                __leave2;
            }
            auto dlen = sizeof_digest(advisor->hintof_digest(hint_tls_alg->mac));

            constexpr char constexpr_verify_data[] = "verify data";

            binary_t verify_data;

            {
                payload pl;
                pl << new payload_member(binary_t(), constexpr_verify_data);
                pl.select(constexpr_verify_data)->reserve(dlen);
                pl.read(stream, size, pos);

                pl.get_binary(constexpr_verify_data, verify_data);
            }

            {
                // https://tls13.xargs.org/#server-handshake-finished/annotated
                binary_t fin_hash;
                auto hash = protection.get_transcript_hash();
                if (hash) {
                    hash->digest(fin_hash);
                    hash->release();
                }

                // calculate finished "tls13 finished"
                // fin_key : expanded
                // finished == maced
                tls_secret_t typeof_secret;
                binary_t fin_key;
                binary_t maced;
                auto tlsversion = protection.get_tls_version();
                if (is_basedon_tls13(tlsversion)) {
                    if (from_server == dir) {
                        typeof_secret = tls_secret_s_hs_traffic;
                    } else {
                        typeof_secret = tls_secret_c_hs_traffic;
                    }
                    const binary_t& ht_secret = protection.get_item(typeof_secret);
                    hash_algorithm_t hashalg = tlsadvisor->hash_alg_of(protection.get_cipher_suite());
                    openssl_kdf kdf;
                    binary_t context;
                    if (session->get_tls_protection().is_kindof_dtls()) {
                        kdf.hkdf_expand_dtls13_label(fin_key, hashalg, dlen, ht_secret, str2bin("finished"), context);
                    } else {
                        kdf.hkdf_expand_tls13_label(fin_key, hashalg, dlen, ht_secret, str2bin("finished"), context);
                    }
                    crypto_hmac_builder builder;
                    crypto_hmac* hmac = builder.set(hashalg).set(fin_key).build();
                    if (hmac) {
                        hmac->mac(fin_hash, maced);
                        hmac->release();
                    }
                } else {
                    binary_t seed;
                    if (from_client == dir) {
                        binary_append(seed, "client finished");
                    } else {
                        binary_append(seed, "server finished");
                    }
                    binary_append(seed, fin_hash);

                    typeof_secret = tls_secret_master;
                    const binary_t& fin_key = protection.get_item(typeof_secret);
                    auto hmac_alg = algof_mac1(hint_tls_alg);

                    crypto_hmac_builder builder;
                    auto hmac = builder.set(hmac_alg).set(fin_key).build();
                    size_t size_maced = 12;
                    if (hmac) {
                        binary_t temp = seed;
                        binary_t atemp;
                        binary_t ptemp;
                        while (maced.size() < size_maced) {
                            hmac->mac(temp, atemp);
                            hmac->update(atemp).update(seed).finalize(ptemp);
                            binary_append(maced, ptemp);
                            temp = atemp;
                        }
                        hmac->release();
                        maced.resize(size_maced);
                    }
                }

                verify_data.resize(maced.size());
                if (verify_data != maced) {
                    ret = errorcode_t::error_verify;
                }

                if (debugstream) {
                    debugstream->autoindent(1);
                    debugstream->printf("> %s\n", constexpr_verify_data);
                    dump_memory(verify_data, debugstream, 16, 3, 0x00, dump_notrunc);
                    debugstream->printf("  > secret (internal) 0x%08x\n", typeof_secret);
                    debugstream->printf("  > verify data %s \n", base16_encode(verify_data).c_str());
                    debugstream->printf("  > maced       %s \e[1;33m%s\e[0m\n", base16_encode(maced).c_str(), (errorcode_t::success == ret) ? "true" : "false");
                    debugstream->autoindent(0);
                }
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
