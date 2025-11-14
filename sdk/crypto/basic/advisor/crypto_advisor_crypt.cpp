/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>

namespace hotplace {
namespace crypto {

const hint_blockcipher_t* crypto_advisor::hintof_blockcipher(crypt_algorithm_t alg) {
    const hint_blockcipher_t* item = nullptr;
    t_maphint<uint32, const hint_blockcipher_t*> hint(_blockcipher_map);

    hint.find(alg, &item);
    return item;
}

const hint_blockcipher_t* crypto_advisor::hintof_blockcipher(const char* alg) {
    const hint_blockcipher_t* ret_value = nullptr;
    if (alg) {
        t_maphint<std::string, const hint_cipher_t*> hint(_cipher_byname_map);
        const hint_cipher_t* item = nullptr;
        hint.find(alg, &item);
        if (item) {
            ret_value = hintof_blockcipher(typeof_alg(item));
        }
    }
    return ret_value;
}

const hint_blockcipher_t* crypto_advisor::hintof_blockcipher(crypto_scheme_t scheme) {
    const hint_blockcipher_t* ret_value = nullptr;
    t_maphint<crypto_scheme_t, const hint_cipher_t*> hint(_cipher_scheme_map);
    const hint_cipher_t* item = nullptr;
    hint.find(scheme, &item);
    if (item) {
        ret_value = hintof_blockcipher(typeof_alg(item));
    }
    return ret_value;
}

const hint_blockcipher_t* crypto_advisor::find_evp_cipher(const EVP_CIPHER* cipher) {
    const hint_blockcipher_t* blockcipher = nullptr;
    return_t ret = errorcode_t::success;

    __try2 {
        const hint_cipher_t* hint = nullptr;
        t_maphint<const EVP_CIPHER*, const hint_cipher_t*> hint_cipher(_evp_cipher_map);
        ret = hint_cipher.find(cipher, &hint);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        t_maphint<uint32, const hint_blockcipher_t*> hint_blockcipher(_blockcipher_map);
        hint_blockcipher.find(typeof_alg(hint), &blockcipher);
    }
    __finally2 {}
    return blockcipher;
}

const EVP_CIPHER* crypto_advisor::find_evp_cipher(crypt_algorithm_t algorithm, crypt_mode_t mode) {
    EVP_CIPHER* ret_value = nullptr;
    uint32 key = CRYPTO_SCHEME16(algorithm, mode);
    t_maphint<uint32, EVP_CIPHER*> hint(_cipher_map);

    hint.find(key, &ret_value);
    return ret_value;
}

const EVP_CIPHER* crypto_advisor::find_evp_cipher(const char* name) {
    const EVP_CIPHER* ret_value = nullptr;

    if (name) {
        t_maphint<std::string, const hint_cipher_t*> hint(_cipher_byname_map);
        const hint_cipher_t* item = nullptr;
        hint.find(name, &item);
        if (item) {
            ret_value = _cipher_map[CRYPTO_SCHEME16(typeof_alg(item), typeof_mode(item))];
        }
    }
    return ret_value;
}

const hint_cipher_t* crypto_advisor::hintof_cipher(const char* name) {
    const hint_cipher_t* ret_value = nullptr;
    __try2 {
        if (nullptr == name) {
            __leave2;
        }

        t_maphint<std::string, const hint_cipher_t*> hint(_cipher_byname_map);
        hint.find(name, &ret_value);
    }
    __finally2 {}
    return ret_value;
}

const hint_cipher_t* crypto_advisor::hintof_cipher(crypt_algorithm_t algorithm, crypt_mode_t mode) {
    const hint_cipher_t* ret_value = nullptr;
    t_maphint<uint32, const hint_cipher_t*> hint(_cipher_fetch_map);
    hint.find(CRYPTO_SCHEME16(algorithm, mode), &ret_value);
    return ret_value;
}

const hint_cipher_t* crypto_advisor::hintof_cipher(const EVP_CIPHER* cipher) {
    const hint_cipher_t* ret_value = nullptr;

    __try2 {
        if (nullptr == cipher) {
            __leave2;
        }

        t_maphint<const EVP_CIPHER*, const hint_cipher_t*> hint(_evp_cipher_map);
        hint.find(cipher, &ret_value);
    }
    __finally2 {}
    return ret_value;
}

const hint_cipher_t* crypto_advisor::hintof_cipher(crypto_scheme_t scheme) {
    const hint_cipher_t* ret_value = nullptr;
    t_maphint<crypto_scheme_t, const hint_cipher_t*> hint(_cipher_scheme_map);
    hint.find(scheme, &ret_value);
    return ret_value;
}

const char* crypto_advisor::nameof_cipher(crypt_algorithm_t algorithm, crypt_mode_t mode) {
    return_t ret = errorcode_t::success;
    const char* ret_value = nullptr;

    __try2 {
        uint32 key = CRYPTO_SCHEME16(algorithm, mode);
        const hint_cipher_t* item = nullptr;
        t_maphint<uint32, const hint_cipher_t*> hint(_cipher_fetch_map);

        ret = hint.find(key, &item);
        ret_value = nameof_alg(item);
    }
    __finally2 {}
    return ret_value;
}

return_t crypto_advisor::for_each_cipher(std::function<void(const char*, uint32, void*)> f, void* user) {
    return_t ret = errorcode_t::success;
    for (auto i = 0; i < sizeof_evp_cipher_methods; i++) {
        const hint_cipher_t* item = evp_cipher_methods + i;
        f(nameof_alg(item), advisor_feature_cipher, user);
    }
    for (auto i = 0; i < sizeof_aes_wrap_methods; i++) {
        const openssl_evp_cipher_method_older_t* item = aes_wrap_methods + i;
        f(item->method.fetchname, advisor_feature_wrap, user);
    }
    return ret;
}

return_t crypto_advisor::for_each_cipher(std::function<void(const hint_cipher_t*)> func) {
    return_t ret = errorcode_t::success;
    for (auto i = 0; i < sizeof_evp_cipher_methods; i++) {
        const hint_cipher_t* item = evp_cipher_methods + i;
        func(item);
    }
    return ret;
}

// hint_blockcipher_t

crypt_algorithm_t typeof_alg(const hint_blockcipher_t* hint) {
    crypt_algorithm_t ret_value = crypt_alg_unknown;
    if (hint) {
        ret_value = hint->algorithm;
    }
    return ret_value;
}

uint16 sizeof_key(const hint_blockcipher_t* hint) {
    uint16 ret_value = 0;
    if (hint) {
        ret_value = hint->keysize;
    }
    return ret_value;
}

uint16 sizeof_iv(const hint_blockcipher_t* hint) {
    uint16 ret_value = 0;
    if (hint) {
        ret_value = hint->ivsize;
    }
    return ret_value;
}

uint16 sizeof_block(const hint_blockcipher_t* hint) {
    uint16 ret_value = 0;
    if (hint) {
        ret_value = hint->blocksize;
    }
    return ret_value;
}

// hint_cipher_t

crypto_scheme_t typeof_sheme(const hint_cipher_t* hint) {
    crypto_scheme_t ret_value = crypto_scheme_unknown;
    if (hint) {
        ret_value = hint->scheme;
    }
    return ret_value;
}

crypt_algorithm_t typeof_alg(const hint_cipher_t* hint) {
    crypt_algorithm_t ret_value = crypt_alg_unknown;
    if (hint) {
        ret_value = hint->algorithm;
    }
    return ret_value;
}

crypt_mode_t typeof_mode(const hint_cipher_t* hint) {
    crypt_mode_t ret_value = mode_unknown;
    if (hint) {
        ret_value = hint->mode;
    }
    return ret_value;
}

const char* nameof_alg(const hint_cipher_t* hint) {
    const char* ret_value = nullptr;
    if (hint) {
        ret_value = hint->fetchname;
    }
    return ret_value;
}

}  // namespace crypto
}  // namespace hotplace
