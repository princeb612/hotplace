/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/nostd/exception.hpp>
#include <sdk/base/system/types.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_kdf.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>

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

        if (0 == dlen) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

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
        EVP_PKEY_CTX_set1_hkdf_key(ctx, key.empty() ? nullptr : &key[0], key.size());
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.empty() ? nullptr : &salt[0], salt.size());
        EVP_PKEY_CTX_add1_hkdf_info(ctx, info.empty() ? nullptr : &info[0], info.size());

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
    __finally2 {}
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
                throw exception(errorcode_t::unexpected);
            }

            binary_t temp;
            temp.resize(size);
            ret = mac.hmac(alg, temp, ikm, prk);
        } else {
            ret = mac.hmac(alg, salt, ikm, prk);
        }
    }
    __finally2 {}
    return ret;
}

return_t openssl_kdf::hmac_kdf_extract(binary_t& prk, hash_algorithm_t alg, const binary_t& salt, const binary_t& ikm) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        const hint_digest_t* hint = advisor->hintof_digest(alg);
        if (nullptr == hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        ret = hmac_kdf_extract(prk, nameof_alg(hint), salt, ikm);
    }
    __finally2 {}
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
    __finally2 {}
    return ret;
}

return_t openssl_kdf::hkdf_expand(binary_t& okm, hash_algorithm_t alg, size_t dlen, const binary_t& prk, const binary_t& info) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    return hkdf_expand(okm, advisor->nameof_md(alg), dlen, prk, info);
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
    __finally2 {}
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
            throw exception(errorcode_t::unexpected);
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
        hash.hash(mac_handle, ikm.empty() ? nullptr : &ikm[0], ikm.size(), prk);
        hash.close(mac_handle);
    }
    __finally2 {}
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
            hash.open(&mac_handle, alg, crypt_mode_t::ecb, prk.empty() ? nullptr : &prk[0], prk.size());
            hash.hash(mac_handle, &content[0], content.size(), t_block);
            hash.close(mac_handle);

            okm.insert(okm.end(), t_block.begin(), t_block.end());  // T = T(1) | T(2) | T(3) | ... | T(N)
            offset += t_block.size();
        }
        okm.resize(dlen);  // OKM = first L octets of T
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
