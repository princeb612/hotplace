/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_aead.hpp>
#include <hotplace/sdk/crypto/basic/crypto_hash.hpp>
#include <hotplace/sdk/crypto/basic/crypto_hmac.hpp>
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>
#include <hotplace/sdk/crypto/basic/openssl_ecdh.hpp>
#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>
#include <hotplace/sdk/crypto/basic/openssl_kdf.hpp>
#include <hotplace/sdk/crypto/basic/transcript_hash.hpp>
#include <hotplace/sdk/net/tls/sslkeylog_exporter.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

return_t tls_protection::calc_finished(tls_direction_t dir, hash_algorithm_t alg, uint16 dlen, tls_secret_t &typeof_secret, binary_t &maced) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (hash_alg_unknown == alg) {
            ret = errorcode_t::unknown;
            __leave2;
        }
        tls_advisor *tlsadvisor = tls_advisor::get_instance();

        auto cs = get_cipher_suite();
        const tls_cipher_suite_t *hint = tlsadvisor->hintof_cipher_suite(cs);

        // https://tls13.xargs.org/#server-handshake-finished/annotated
        binary_t fin_hash;
        auto hash = get_transcript_hash();
        if (hash) {
            hash->digest(fin_hash);
            hash->release();
        }

        // calculate finished "tls13 finished"
        // fin_key : expanded
        // finished == maced

        binary_t fin_key;
        if (is_kindof_tls13()) {
            if (is_serverinitiated(dir)) {
                typeof_secret = tls_secret_s_hs_traffic;
            } else if (is_clientinitiated(dir)) {
                typeof_secret = tls_secret_c_hs_traffic;
            }
            const binary_t &ht_secret = get_secrets().get(typeof_secret);
            hash_algorithm_t hashalg = tlsadvisor->algof_hash(get_cipher_suite());
            openssl_kdf kdf;
            binary_t context;
            if (is_kindof_dtls()) {
                kdf.hkdf_expand_dtls13_label(fin_key, hashalg, dlen, ht_secret, "finished", context);
            } else {
                kdf.hkdf_expand_tls13_label(fin_key, hashalg, dlen, ht_secret, "finished", context);
            }
            crypto_hmac_builder builder;
            crypto_hmac *hmac = builder.set(hashalg).set(fin_key).build();
            if (hmac) {
                hmac->mac(fin_hash, maced);
                hmac->release();
            }
#if defined DEBUG
            if (istraceable(trace_category_net)) {
                trace_debug_event(trace_category_net, trace_event_tls_protection, [&](basic_stream &dbs) -> void {
                    dbs.println("> finished");
                    dbs.println("  key   %s", base16_encode(fin_key).c_str());
                    dbs.println("  hash  %s", base16_encode(fin_hash).c_str());
                    dbs.println("  maced %s", base16_encode(maced).c_str());
                });
            }
#endif
        } else {
            binary_t seed;
            if (is_clientinitiated(dir)) {
                binary_append(seed, "client finished");
            } else if (is_serverinitiated(dir)) {
                binary_append(seed, "server finished");
            }
            binary_append(seed, fin_hash);

            typeof_secret = tls_secret_master;
            const binary_t &fin_key = get_secrets().get(typeof_secret);

            crypto_hmac_builder builder;
            auto hmac = builder.set(alg).set(fin_key).build();
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
#if defined DEBUG
            if (istraceable(trace_category_net)) {
                trace_debug_event(trace_category_net, trace_event_tls_protection, [&](basic_stream &dbs) -> void {
                    dbs.println("> finished");
                    dbs.println("  key   %s", base16_encode(fin_key).c_str());
                    dbs.println("  hash  %s", base16_encode(fin_hash).c_str());
                    dbs.println("  maced %s", base16_encode(maced).c_str());
                });
            }
#endif
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
