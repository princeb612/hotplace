/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 6070 PKCS #5: Password-Based Key Derivation Function 2 (PBKDF2)
 *  RFC 7914 The scrypt Password-Based Key Derivation Function
 *  RFC 9106 Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications
 *  - openssl-3.2 required
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/system/types.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_kdf.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>
#include <sdk/io/basic/payload.hpp>

#if defined __linux__
#include <dlfcn.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace hotplace {
namespace crypto {

openssl_kdf::openssl_kdf() {}

openssl_kdf::~openssl_kdf() {}

return_t openssl_kdf::hkdf(binary_t& derived, hash_algorithm_t alg, size_t dlen, const binary_t& ikm, const binary_t& salt, const binary_t& info) {
    return hmac_kdf(derived, alg, dlen, ikm, salt, info);
}

return_t openssl_kdf::hmac_kdf(binary_t& derived, hash_algorithm_t alg, size_t dlen, const binary_t& key, const binary_t& salt, const binary_t& info) {
    return_t ret = errorcode_t::success;
    EVP_PKEY_CTX* ctx = nullptr;
    int ret_openssl = 0;
    const EVP_MD* md = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        derived.clear();

        md = advisor->find_evp_md(alg);
        if (nullptr == md) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        if (nullptr == ctx) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_CTX_set_hkdf_md(ctx, md);
        EVP_PKEY_CTX_set1_hkdf_key(ctx, &key[0], key.size());
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, &salt[0], salt.size());
        EVP_PKEY_CTX_add1_hkdf_info(ctx, &info[0], info.size());

        derived.resize(dlen);
        ret_openssl = EVP_PKEY_derive(ctx, &derived[0], &dlen);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
    }
    __finally2 {
        if (ctx) {
            EVP_PKEY_CTX_free(ctx);
        }
    }
    return ret;
}

return_t openssl_kdf::hkdf(binary_t& derived, const char* alg, size_t dlen, const binary_t& ikm, const binary_t& salt, const binary_t& info) {
    return hmac_kdf(derived, alg, dlen, ikm, salt, info);
}

return_t openssl_kdf::hmac_kdf(binary_t& derived, const char* alg, size_t dlen, const binary_t& key, const binary_t& salt, const binary_t& info) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        derived.clear();

        if (nullptr == alg) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const hint_digest_t* hint = advisor->hintof_digest(alg);
        if (nullptr == hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        ret = hmac_kdf(derived, typeof_alg(hint), dlen, key, salt, info);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_kdf::hmac_kdf_extract(binary_t& prk, const char* alg, const binary_t& salt, const binary_t& ikm) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    openssl_mac mac;

    __try2 {
        prk.clear();

        if (nullptr == alg) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (0 == salt.size()) {
            // #if OPENSSL_VERSION_NUMBER >= 0x30000000L
            // const EVP_MD* md = advisor->find_evp_md(alg);
            // size = EVP_MD_get_block_size(md);
            // #endif
            const hint_digest_t* hint = advisor->hintof_digest(alg);
            if (nullptr == hint) {
                ret = errorcode_t::not_found;
                __leave2;
            }
            uint16 size = sizeof_digest(hint);
            if (0 == size) {
                throw;
            }

            binary_t temp;
            temp.resize(size);
            ret = mac.hmac(alg, temp, ikm, prk);
        } else {
            ret = mac.hmac(alg, salt, ikm, prk);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_kdf::hkdf_expand(binary_t& okm, const char* alg, size_t dlen, const binary_t& prk, const binary_t& info) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        okm.clear();

        if (nullptr == alg) {
            __leave2;
        }

        const hint_digest_t* hint = advisor->hintof_digest(alg);
        if (nullptr == hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        size_t digest_size = sizeof_digest(hint);
        size_t prk_size = prk.size();

        if (dlen > digest_size * 255) {
            ret = errorcode_t::out_of_range;
            __leave2;
        }

        okm.clear();

        uint32 offset = 0;
        binary_t t_block;  // T(0) = empty string (zero length)
        for (uint32 i = 1; offset < dlen /* N = ceil(L/Hash_Size) */; i++) {
            binary_t content;  // T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
            content.insert(content.end(), t_block.begin(), t_block.end());
            content.insert(content.end(), info.begin(), info.end());
            content.insert(content.end(), i);  // i = 1..255 (01..ff)

            openssl_mac mac;
            mac.hmac(alg, prk, content, t_block);  // T(i) = HMAC-Hash(PRK, T(i-1) | info | i), i = 1..255 (01..ff)

            okm.insert(okm.end(), t_block.begin(), t_block.end());  // T = T(1) | T(2) | T(3) | ... | T(N)
            offset += t_block.size();
        }
        okm.resize(dlen);  // OKM = first L octets of T
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_kdf::hkdf_expand(binary_t& okm, hash_algorithm_t alg, size_t dlen, const binary_t& prk, const binary_t& info) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    return hkdf_expand(okm, advisor->nameof_md(alg), dlen, prk, info);
}

return_t openssl_kdf::hkdf_expand_aes_rfc8152(binary_t& okm, const char* alg, size_t dlen, const binary_t& prk, const binary_t& info) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    EVP_CIPHER_CTX* context = nullptr;
    openssl_mac mac;

    __try2 {
        // the CKDF-Expand(PRK, info, L) function takes the PRK result from CKDF-Extract, an arbitrary "info" argument and a requested number of bytes to
        // produce. It calculates the L-byte result, called the "output keying material" (OKM)

        okm.clear();

        if (nullptr == alg) {
            __leave2;
        }

        const hint_blockcipher_t* hint = advisor->hintof_blockcipher(alg);
        if (nullptr == hint) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        const EVP_CIPHER* cipher = advisor->find_evp_cipher(alg);
        if (nullptr == cipher) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        context = EVP_CIPHER_CTX_new();
        if (nullptr == context) {
            ret = errorcode_t::out_of_memory;
            __leave2;
        }

        binary_t iv;
        uint16 blocksize = sizeof_block(hint);
        uint32 offset = 0;
        binary_t t_block;  // T(0) = empty string (zero length)
        int t_block_size = 0;
        int size_update = 0;
        iv.resize(16);

        EVP_CIPHER_CTX_set_padding(context, 1);

        for (uint32 i = 1; offset < dlen /* N = ceil(L/Hash_Size) */; i++) {
            binary_t content;  // T(1) = AES-CMAC(PRK, T(0) | info | 0x01)
            content.insert(content.end(), t_block.begin(), t_block.end());
            content.insert(content.end(), info.begin(), info.end());
            content.insert(content.end(), i);  // i = 1..255 (01..ff)

            // T(i) = AES-CMAC(PRK, T(i-1) | info | i), i = 1..255 (01..ff)
            if (!t_block_size) {
                t_block_size = blocksize;
                t_block.resize(blocksize);
            }

            EVP_CipherInit_ex(context, cipher, nullptr, &prk[0], &iv[0], 1);

            int size_update = 0;
            size_t size_input = content.size();
            for (size_t j = 0; j < size_input; j += blocksize) {
                int remain = size_input - j;
                int size = (remain < blocksize) ? remain : blocksize;
                if (remain > blocksize) {
                    EVP_CipherUpdate(context, &t_block[0], &size_update, &content[j], blocksize);
                } else {
                    EVP_CipherUpdate(context, &t_block[0], &size_update, &content[j], remain);
                    EVP_CipherUpdate(context, &t_block[0], &size_update, &iv[0], blocksize - remain);
                }
            }

            okm.insert(okm.end(), t_block.begin(), t_block.end());  // T = T(1) | T(2) | T(3) | ... | T(N)
            offset += t_block.size();
        }
        okm.resize(dlen);  // OKM = first L octets of T
    }
    __finally2 {
        if (context) {
            EVP_CIPHER_CTX_free(context);
        }
    }
    return ret;
}

return_t openssl_kdf::hkdf_expand_label(binary_t& okm, const char* alg, uint16 length, const binary_t& secret, const binary_t& label, const binary_t& context) {
    return_t ret = errorcode_t::success;
    __try2 {
        okm.clear();

        if (label.empty() || (label.size() > 255) || (context.size() > 255)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        /**
         * RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
         *  7.  Cryptographic Computations
         *   HKDF-Expand-Label(Secret, Label, Context, Length) = HKDF-Expand(Secret, HkdfLabel, Length)
         *
         * RFC 9001 Using TLS to Secure QUIC
         *  Appendix A.  Sample Packet Protection
         */

        binary_t bin_hkdflabel;
        uint8 opaque_len_label = 6 + label.size();  // length including "tls13 "
        uint8 opaque_len_context = context.size();
#if 0  // tested
        payload pl;
        pl << new payload_member(length, true) << new payload_member(opaque_len_label) << new payload_member(std::string("tls13 ")) << new payload_member(label)
           << new payload_member(opaque_len_context) << new payload_member(context);
        pl.write(bin_hkdflabel);
#else
        binary_append(bin_hkdflabel, length, hton16);
        binary_append(bin_hkdflabel, opaque_len_label);
        binary_append(bin_hkdflabel, "tls13 ", 6);
        binary_append(bin_hkdflabel, label);
        binary_append(bin_hkdflabel, opaque_len_context);
        binary_append(bin_hkdflabel, context);
#endif
        /**
         * RFC 5869
         * HKDF-Expand(PRK, info, L) -> OKM
         */
        openssl_kdf kdf;
        kdf.hkdf_expand(okm, alg, length, secret, bin_hkdflabel);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_kdf::hkdf_expand_label(binary_t& okm, hash_algorithm_t alg, uint16 length, const binary_t& secret, const binary_t& label,
                                        const binary_t& context) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    return hkdf_expand_label(okm, advisor->nameof_md(alg), length, secret, label, context);
}

return_t openssl_kdf::ckdf(binary_t& okm, crypt_algorithm_t alg, size_t dlen, const binary_t& ikm, const binary_t& salt, const binary_t& info) {
    return cmac_kdf(okm, alg, dlen, ikm, salt, info);
}

return_t openssl_kdf::cmac_kdf(binary_t& okm, crypt_algorithm_t alg, size_t dlen, const binary_t& ikm, const binary_t& salt, const binary_t& info) {
    return_t ret = errorcode_t::success;
    binary_t prk;
    __try2 {
        okm.clear();

        ret = cmac_kdf_extract(prk, alg, salt, ikm);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = cmac_kdf_expand(okm, alg, dlen, prk, info);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_kdf::cmac_kdf_extract(binary_t& prk, crypt_algorithm_t alg, const binary_t& salt, const binary_t& ikm) {
    // RFC 4615 Figure 1.  The AES-CMAC-PRF-128 Algorithm
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    openssl_hash hash;
    hash_context_t* mac_handle = nullptr;

    __try2 {
        prk.clear();

        const hint_blockcipher_t* hint = advisor->hintof_blockcipher(alg);
        uint16 blocksize = sizeof_block(hint);

        if (0 == blocksize) {
            throw;
        }
        auto algorithm = typeof_alg(hint);

        binary_t k;
        if (0 == salt.size()) {
            // If no salt is given, the 16-byte, all-zero value is used.
            // step 1a.
            k.resize(blocksize);
        } else if (blocksize == salt.size()) {
            // step 1.
            // step 1a.
            k = salt;
        } else {
            // step 1b.
            binary_t o128;
            o128.resize(blocksize);

            hash.open(&mac_handle, algorithm, crypt_mode_t::cbc, &o128[0], o128.size());
            hash.hash(mac_handle, &salt[0], salt.size(), k);
            hash.close(mac_handle);
        }

        // step 2.
        hash.open(&mac_handle, algorithm, crypt_mode_t::cbc, &k[0], k.size());
        hash.hash(mac_handle, &ikm[0], ikm.size(), prk);
        hash.close(mac_handle);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_kdf::cmac_kdf_expand(binary_t& okm, crypt_algorithm_t alg, size_t dlen, const binary_t& prk, const binary_t& info) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    openssl_hash hash;

    __try2 {
        /**
         * the CKDF-Expand(PRK, info, L) function takes the PRK result from CKDF-Extract, an arbitrary "info" argument and a requested number of bytes to
         * produce. It calculates the L-byte result, called the "output keying material" (OKM)
         */

        okm.clear();

        const hint_blockcipher_t* hint = advisor->hintof_blockcipher(alg);
        uint16 blocksize = sizeof_block(hint);

        uint32 offset = 0;
        binary_t t_block;  // T(0) = empty string (zero length)
        for (uint32 i = 1; offset < dlen /* N = ceil(L/Hash_Size) */; i++) {
            binary_t content;  // T(1) = AES-CMAC(PRK, T(0) | info | 0x01)
            content.insert(content.end(), t_block.begin(), t_block.end());
            content.insert(content.end(), info.begin(), info.end());
            content.insert(content.end(), i);  // i = 1..255 (01..ff)

            // T(i) = AES-CMAC(PRK, T(i-1) | info | i), i = 1..255 (01..ff)
            hash_context_t* mac_handle = nullptr;
            hash.open(&mac_handle, alg, crypt_mode_t::ecb, &prk[0], prk.size());
            hash.hash(mac_handle, &content[0], content.size(), t_block);
            hash.close(mac_handle);

            okm.insert(okm.end(), t_block.begin(), t_block.end());  // T = T(1) | T(2) | T(3) | ... | T(N)
            offset += t_block.size();
        }
        okm.resize(dlen);  // OKM = first L octets of T
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_kdf::pbkdf2(binary_t& derived, hash_algorithm_t alg, size_t dlen, const std::string& password, const binary_t& salt, int iter) {
    return pbkdf2(derived, alg, dlen, password.c_str(), password.size(), &salt[0], salt.size(), iter);
}

return_t openssl_kdf::pbkdf2(binary_t& derived, const char* alg, size_t dlen, const std::string& password, const binary_t& salt, int iter) {
    return pbkdf2(derived, alg, dlen, password.c_str(), password.size(), &salt[0], salt.size(), iter);
}

return_t openssl_kdf::pbkdf2(binary_t& derived, hash_algorithm_t alg, size_t dlen, const binary_t& password, const binary_t& salt, int iter) {
    return pbkdf2(derived, alg, dlen, (char*)&password[0], password.size(), &salt[0], salt.size(), iter);
}

return_t openssl_kdf::pbkdf2(binary_t& derived, const char* alg, size_t dlen, const binary_t& password, const binary_t& salt, int iter) {
    return pbkdf2(derived, alg, dlen, (char*)&password[0], password.size(), &salt[0], salt.size(), iter);
}

return_t openssl_kdf::pbkdf2(binary_t& derived, hash_algorithm_t alg, size_t dlen, const char* password, size_t size_password, const byte_t* salt,
                             size_t size_salt, int iter) {
    return_t ret = errorcode_t::success;
    const EVP_MD* md = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        derived.clear();

        if (nullptr == password || nullptr == salt) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        md = advisor->find_evp_md(alg);
        if (nullptr == md) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        derived.resize(dlen);
        PKCS5_PBKDF2_HMAC(password, size_password, salt, size_salt, iter, md, dlen, &derived[0]);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_kdf::pbkdf2(binary_t& derived, const char* alg, size_t dlen, const char* password, size_t size_password, const byte_t* salt, size_t size_salt,
                             int iter) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        derived.clear();

        if (nullptr == alg) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const hint_digest_t* hint = advisor->hintof_digest(alg);
        if (nullptr == hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        ret = pbkdf2(derived, typeof_alg(hint), dlen, password, size_password, salt, size_salt, iter);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_kdf::scrypt(binary_t& derived, size_t dlen, const std::string& password, const binary_t& salt, int n, int r, int p) {
    return_t ret = errorcode_t::success;
    EVP_PKEY_CTX* ctx = nullptr;
    int ret_openssl = 0;
    __try2 {
        derived.clear();

#if OPENSSL_VERSION_NUMBER < 0x30000000L
        if (0 == salt.size()) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
#endif
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, nullptr);
        if (nullptr == ctx) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_CTX_set1_pbe_pass(ctx, password.c_str(), password.size());
        EVP_PKEY_CTX_set1_scrypt_salt(ctx, &salt[0], salt.size());
        EVP_PKEY_CTX_set_scrypt_N(ctx, n);
        EVP_PKEY_CTX_set_scrypt_r(ctx, r);
        EVP_PKEY_CTX_set_scrypt_p(ctx, p);

        derived.resize(dlen);
        ret_openssl = EVP_PKEY_derive(ctx, &derived[0], &dlen);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
    }
    __finally2 {
        if (ctx) {
            EVP_PKEY_CTX_free(ctx);
        }
    }
    return ret;
}

return_t openssl_kdf::argon2(binary_t& derived, argon2_t mode, size_t dlen, const binary_t& password, const binary_t& salt, const binary_t& ad,
                             const binary_t& secret, uint32 iteration_cost, uint32 parallel_cost, uint32 memory_cost) {
    return_t ret = errorcode_t::success;

    derived.clear();

#if OPENSSL_VERSION_NUMBER >= 0x30200000L

    int ret_openssl = 0;
    EVP_KDF* kdf = nullptr;
    EVP_KDF_CTX* ctx = nullptr;
    OSSL_LIB_CTX* lib_context = nullptr;
    OSSL_PARAM params[9], *p = params;
    unsigned int threads = 0;

    __try2 {
        const char* id = nullptr;
        switch (mode) {
            case argon2_t::argon2d:
                id = "argon2d";
                break;
            case argon2_t::argon2i:
                id = "argon2i";
                break;
            case argon2_t::argon2id:
                id = "argon2id";
                break;
            default:
                break;
        }
        if (nullptr == id) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        lib_context = OSSL_LIB_CTX_new();
        if (nullptr == lib_context) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        kdf = EVP_KDF_fetch(lib_context, id, nullptr);
        if (nullptr == kdf) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ctx = EVP_KDF_CTX_new(kdf);
        if (nullptr == ctx) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        threads = parallel_cost;
        ret_openssl = OSSL_set_max_threads(lib_context, parallel_cost);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        /* Set password */
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void*)&password[0], password.size());
        /* Set salt */
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void*)&salt[0], salt.size());
        /* Set optional additional data */
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_ARGON2_AD, (void*)&ad[0], ad.size());
        /* Set optional secret */
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, (void*)&secret[0], secret.size());
        /* Set iteration count */
        *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, (uint32_t*)&iteration_cost);
        /* Set threads performing derivation (can be decreased) */
        *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_THREADS, &threads);
        /* Set parallel cost */
        *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, (uint32_t*)&parallel_cost);
        /* Set memory requirement */
        *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, (uint32_t*)&memory_cost);
        *p = OSSL_PARAM_construct_end();

        derived.resize(dlen);
        ret_openssl = EVP_KDF_derive(ctx, &derived[0], dlen, params);
    }
    __finally2 {
        if (ctx) {
            EVP_KDF_CTX_free(ctx);
        }
        if (kdf) {
            EVP_KDF_free(kdf);
        }
        if (lib_context) {
            OSSL_LIB_CTX_free(lib_context);
        }
    }
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t openssl_kdf::argon2d(binary_t& derived, size_t dlen, const binary_t& password, const binary_t& salt, const binary_t& ad, const binary_t& secret,
                              uint32 iteration_cost, uint32 parallel_cost, uint32 memory_cost) {
    return argon2(derived, argon2_t::argon2d, dlen, password, salt, ad, secret, iteration_cost, parallel_cost, memory_cost);
}

return_t openssl_kdf::argon2i(binary_t& derived, size_t dlen, const binary_t& password, const binary_t& salt, const binary_t& ad, const binary_t& secret,
                              uint32 iteration_cost, uint32 parallel_cost, uint32 memory_cost) {
    return argon2(derived, argon2_t::argon2i, dlen, password, salt, ad, secret, iteration_cost, parallel_cost, memory_cost);
}

return_t openssl_kdf::argon2id(binary_t& derived, size_t dlen, const binary_t& password, const binary_t& salt, const binary_t& ad, const binary_t& secret,
                               uint32 iteration_cost, uint32 parallel_cost, uint32 memory_cost) {
    return argon2(derived, argon2_t::argon2id, dlen, password, salt, ad, secret, iteration_cost, parallel_cost, memory_cost);
}

}  // namespace crypto
}  // namespace hotplace
