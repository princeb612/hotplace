/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <iostream>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/io/system/sdk.hpp>

namespace hotplace {
namespace crypto {

/* something wrong EVP_CIPHER_CTX_iv_length, EVP_CIPHER_CTX_block_size (openssl-1.1.1) */
const hint_blockcipher_t hint_blockciphers[] = {
    // 16 (128), 24 (192), 32 (256)

    {
        crypt_algorithm_t::aes128,
        16,
        16,
        16,
        16,
    },
    {
        crypt_algorithm_t::aes192,
        24,
        16,
        16,
        24,
    },
    {
        crypt_algorithm_t::aes256,
        32,
        16,
        16,
        32,
    },
    {
        crypt_algorithm_t::blowfish,
        16,
        8,
        8,
    },

    {
        crypt_algorithm_t::aria128,
        16,
        16,
        16,
    },
    {
        crypt_algorithm_t::aria192,
        24,
        16,
        16,
    },
    {
        crypt_algorithm_t::aria256,
        32,
        16,
        16,
    },

    {
        crypt_algorithm_t::camellia128,
        16,
        16,
        16,
    },
    {
        crypt_algorithm_t::camellia192,
        24,
        16,
        16,
    },
    {
        crypt_algorithm_t::camellia256,
        32,
        16,
        16,
    },

    {
        crypt_algorithm_t::cast,
        16,
        8,
        8,
    },

    {
        crypt_algorithm_t::idea,
        16,
        8,
        8,
    },

    {
        crypt_algorithm_t::rc2,
        8,
        8,
        8,
    },

    {
        crypt_algorithm_t::rc5,
        16,
        8,
        8,
    },

    {
        crypt_algorithm_t::seed,
        16,
        16,
        16,
    },

    {
        crypt_algorithm_t::sm4,
        16,
        16,
        16,
    },

    {
        crypt_algorithm_t::rc4,
        0,
        12,
        0,
    },
    {
        crypt_algorithm_t::chacha20,
        32,
        12,
        0,
    },
};

const size_t sizeof_hint_blockciphers = RTL_NUMBER_OF(hint_blockciphers);

crypt_algorithm_t typeof_alg(const hint_blockcipher_t* hint) {
    crypt_algorithm_t ret_value = crypt_algorithm_t::crypt_alg_unknown;
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

}  // namespace crypto
}  // namespace hotplace
