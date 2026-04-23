/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_protection_calc_keyblock.cpp
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

return_t tls_protection::calc_keyblock(hash_algorithm_t hmac_alg, const binary_t &master_secret, const binary_t &client_hello_random,
                                       const binary_t &server_hello_random, uint16 cs) {
    return_t ret = errorcode_t::success;
    __try2 {
        tls_advisor *tlsadvisor = tls_advisor::get_instance();

        crypto_hmac_builder builder;
        auto hmac_expansion = builder.set(hmac_alg).set(master_secret).build();
        if (hmac_expansion) {
            bool is_cbc = tlsadvisor->is_kindof_cbc(cs);

            /**
             * key expansion
             * RFC 2246 5. HMAC and the pseudorandom function
             * RFC 2246 6.3. Key calculation
             * RFC 5246 6.3.  Key Calculation
             * key_block = PRF(SecurityParameters.master_secret,
             *                    "key expansion",
             *                    SecurityParameters.server_random +
             *                    SecurityParameters.client_random);
             *
             * client_write_MAC_secret[SecurityParameters.hash_size]
             * server_write_MAC_secret[SecurityParameters.hash_size]
             * client_write_key[SecurityParameters.key_material_length]
             * server_write_key[SecurityParameters.key_material_length]
             * client_write_IV[SecurityParameters.IV_size]
             * server_write_IV[SecurityParameters.IV_size]
             */
            binary_t seed;
            binary_append(seed, "key expansion");
            binary_append(seed, server_hello_random);
            binary_append(seed, client_hello_random);

            auto hint_blockcipher = tlsadvisor->hintof_blockcipher(cs);
            auto hint_digest = tlsadvisor->hintof_digest(cs);
            auto hint_cipher = tlsadvisor->hintof_cipher(cs);
            if (nullptr == hint_blockcipher || nullptr == hint_digest) {
                ret = errorcode_t::not_supported;
                __leave2;
            }
            auto mode = typeof_mode(hint_cipher);
            auto keysize = sizeof_key(hint_blockcipher);
            // TLS 1.2 GCM nonce = fixed iv (4) + explitcit iv (8) = 12
            auto ivsize = 0;
            switch (mode) {
                case cbc: {
                    ivsize = sizeof_iv(hint_blockcipher);
                } break;
                case mode_poly1305: {
                    ivsize = 12;
                } break;
                case ccm:
                case gcm: {
                    ivsize = 4;
                } break;
            }
            auto dlen = (is_cbc) ? sizeof_digest(hint_digest) : 0;
            size_t size_keycalc = (dlen << 1) + (keysize << 1) + (ivsize << 1);
            size_t offset = 0;

            // until enough output has been generated
            binary_t p;
            binary_t temp = seed;
            binary_t atemp;
            binary_t ptemp;
            while (p.size() < size_keycalc) {
                hmac_expansion->mac(temp, atemp);
                hmac_expansion->update(atemp).update(seed).finalize(ptemp);
                binary_append(p, ptemp);
                temp = atemp;
            }

            binary_t secret_client_mac_key;
            binary_t secret_server_mac_key;
            binary_t secret_client_key;
            binary_t secret_server_key;
            binary_t secret_client_iv;
            binary_t secret_server_iv;

            // partition
            p.resize(size_keycalc);

            if (is_cbc) {
                binary_append(secret_client_mac_key, &p[offset], dlen);
                offset += dlen;
                binary_append(secret_server_mac_key, &p[offset], dlen);
                offset += dlen;
            }

            binary_append(secret_client_key, &p[offset], keysize);
            offset += keysize;
            binary_append(secret_server_key, &p[offset], keysize);
            offset += keysize;
            binary_append(secret_client_iv, &p[offset], ivsize);
            offset += ivsize;
            binary_append(secret_server_iv, &p[offset], ivsize);
            offset += ivsize;

            if (is_cbc) {
                get_secrets().assign(tls_secret_client_mac_key, secret_client_mac_key);
                get_secrets().assign(tls_secret_server_mac_key, secret_server_mac_key);
            }
            get_secrets().assign(tls_secret_client_key, secret_client_key);
            get_secrets().assign(tls_secret_server_key, secret_server_key);
            get_secrets().assign(tls_secret_client_iv, secret_client_iv);
            get_secrets().assign(tls_secret_server_iv, secret_server_iv);

#if defined DEBUG
            if (istraceable(trace_category_net)) {
                trace_debug_event(trace_category_net, trace_event_tls_protection, [&](basic_stream &dbs) -> void {
                    dbs.printf(ANSI_ESCAPE "1;36m");
                    dbs.println("> cipher_suite %s", tlsadvisor->hintof_cipher_suite(cs)->name_iana);
                    dbs.println("> master_secret %s", base16_encode(master_secret).c_str());
                    dbs.println("> client_hello_random %s", base16_encode(client_hello_random).c_str());
                    dbs.println("> server_hello_random %s", base16_encode(server_hello_random).c_str());
                    dbs.println("> keyblock %s", base16_encode(p).c_str());
                    if (is_cbc) {
                        dbs.println("> secret_client_mac_key[%08x] %s (%zi-octet)", tls_secret_client_mac_key, base16_encode(secret_client_mac_key).c_str(),
                                    secret_client_mac_key.size());
                        dbs.println("> secret_server_mac_key[%08x] %s (%zi-octet)", tls_secret_server_mac_key, base16_encode(secret_server_mac_key).c_str(),
                                    secret_server_mac_key.size());
                    }
                    dbs.println("> secret_client_key[%08x] %s (%zi-octet)", tls_secret_client_key, base16_encode(secret_client_key).c_str(),
                                secret_client_key.size());
                    dbs.println("> secret_server_key[%08x] %s (%zi-octet)", tls_secret_server_key, base16_encode(secret_server_key).c_str(),
                                secret_server_key.size());
                    dbs.println("> secret_client_iv[%08x] %s (%zi-octet)", tls_secret_client_iv, base16_encode(secret_client_iv).c_str(),
                                secret_client_iv.size());
                    dbs.println("> secret_server_iv[%08x] %s (%zi-octet)", tls_secret_server_iv, base16_encode(secret_server_iv).c_str(),
                                secret_server_iv.size());
                    dbs.printf(ANSI_ESCAPE "0m");
                });
            }
#endif

            hmac_expansion->release();
        } else {
            ret = errorcode_t::not_supported;
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
