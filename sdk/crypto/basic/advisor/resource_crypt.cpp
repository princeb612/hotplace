/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_advisor.hpp>

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

const hint_cipher_t evp_cipher_methods[] = {
    {crypt_algorithm_t::aes128, crypt_mode_t::cbc, "aes-128-cbc"},
    {crypt_algorithm_t::aes128, crypt_mode_t::ccm, "aes-128-ccm"},
    {crypt_algorithm_t::aes128, crypt_mode_t::cfb, "aes-128-cfb"},
    {crypt_algorithm_t::aes128, crypt_mode_t::cfb1, "aes-128-cfb1"},
    {crypt_algorithm_t::aes128, crypt_mode_t::cfb8, "aes-128-cfb8"},
    {crypt_algorithm_t::aes128, crypt_mode_t::ctr, "aes-128-ctr"},
    {crypt_algorithm_t::aes128, crypt_mode_t::ecb, "aes-128-ecb"},
    {crypt_algorithm_t::aes128, crypt_mode_t::gcm, "aes-128-gcm"},
    {crypt_algorithm_t::aes128, crypt_mode_t::ofb, "aes-128-ofb"},
    {crypt_algorithm_t::aes128, crypt_mode_t::wrap, "aes-128-wrap"},
    {crypt_algorithm_t::aes128, crypt_mode_t::ccm8, "aes-128-ccm"},

    {crypt_algorithm_t::aes192, crypt_mode_t::cbc, "aes-192-cbc"},
    {crypt_algorithm_t::aes192, crypt_mode_t::ccm, "aes-192-ccm"},
    {crypt_algorithm_t::aes192, crypt_mode_t::cfb, "aes-192-cfb"},
    {crypt_algorithm_t::aes192, crypt_mode_t::cfb1, "aes-192-cfb1"},
    {crypt_algorithm_t::aes192, crypt_mode_t::cfb8, "aes-192-cfb8"},
    {crypt_algorithm_t::aes192, crypt_mode_t::ctr, "aes-192-ctr"},
    {crypt_algorithm_t::aes192, crypt_mode_t::ecb, "aes-192-ecb"},
    {crypt_algorithm_t::aes192, crypt_mode_t::gcm, "aes-192-gcm"},
    {crypt_algorithm_t::aes192, crypt_mode_t::ofb, "aes-192-ofb"},
    {crypt_algorithm_t::aes192, crypt_mode_t::wrap, "aes-192-wrap"},
    {crypt_algorithm_t::aes192, crypt_mode_t::ccm8, "aes-192-ccm"},

    {crypt_algorithm_t::aes256, crypt_mode_t::cbc, "aes-256-cbc"},
    {crypt_algorithm_t::aes256, crypt_mode_t::ccm, "aes-256-ccm"},
    {crypt_algorithm_t::aes256, crypt_mode_t::cfb, "aes-256-cfb"},
    {crypt_algorithm_t::aes256, crypt_mode_t::cfb1, "aes-256-cfb1"},
    {crypt_algorithm_t::aes256, crypt_mode_t::cfb8, "aes-256-cfb8"},
    {crypt_algorithm_t::aes256, crypt_mode_t::ctr, "aes-256-ctr"},
    {crypt_algorithm_t::aes256, crypt_mode_t::ecb, "aes-256-ecb"},
    {crypt_algorithm_t::aes256, crypt_mode_t::gcm, "aes-256-gcm"},
    {crypt_algorithm_t::aes256, crypt_mode_t::ofb, "aes-256-ofb"},
    {crypt_algorithm_t::aes256, crypt_mode_t::wrap, "aes-256-wrap"},
    {crypt_algorithm_t::aes256, crypt_mode_t::ccm8, "aes-256-ccm"},

    {crypt_algorithm_t::aria128, crypt_mode_t::cbc, "aria-128-cbc"},
    {crypt_algorithm_t::aria128, crypt_mode_t::ccm, "aria-128-ccm"},
    {crypt_algorithm_t::aria128, crypt_mode_t::cfb, "aria-128-cfb"},
    {crypt_algorithm_t::aria128, crypt_mode_t::cfb1, "aria-128-cfb1"},
    {crypt_algorithm_t::aria128, crypt_mode_t::cfb8, "aria-128-cfb8"},
    {crypt_algorithm_t::aria128, crypt_mode_t::ctr, "aria-128-ctr"},
    {crypt_algorithm_t::aria128, crypt_mode_t::ecb, "aria-128-ecb"},
    {crypt_algorithm_t::aria128, crypt_mode_t::gcm, "aria-128-gcm"},
    {crypt_algorithm_t::aria128, crypt_mode_t::ofb, "aria-128-ofb"},
    {crypt_algorithm_t::aria128, crypt_mode_t::ccm8, "aria-128-ccm"},

    {crypt_algorithm_t::aria192, crypt_mode_t::cbc, "aria-192-cbc"},
    {crypt_algorithm_t::aria192, crypt_mode_t::ccm, "aria-192-ccm"},
    {crypt_algorithm_t::aria192, crypt_mode_t::cfb, "aria-192-cfb"},
    {crypt_algorithm_t::aria192, crypt_mode_t::cfb1, "aria-192-cfb1"},
    {crypt_algorithm_t::aria192, crypt_mode_t::cfb8, "aria-192-cfb8"},
    {crypt_algorithm_t::aria192, crypt_mode_t::ctr, "aria-192-ctr"},
    {crypt_algorithm_t::aria192, crypt_mode_t::ecb, "aria-192-ecb"},
    {crypt_algorithm_t::aria192, crypt_mode_t::gcm, "aria-192-gcm"},
    {crypt_algorithm_t::aria192, crypt_mode_t::ofb, "aria-192-ofb"},
    {crypt_algorithm_t::aria192, crypt_mode_t::ccm8, "aria-192-ccm"},

    {crypt_algorithm_t::aria256, crypt_mode_t::cbc, "aria-256-cbc"},
    {crypt_algorithm_t::aria256, crypt_mode_t::ccm, "aria-256-ccm"},
    {crypt_algorithm_t::aria256, crypt_mode_t::cfb, "aria-256-cfb"},
    {crypt_algorithm_t::aria256, crypt_mode_t::cfb1, "aria-256-cfb1"},
    {crypt_algorithm_t::aria256, crypt_mode_t::cfb8, "aria-256-cfb8"},
    {crypt_algorithm_t::aria256, crypt_mode_t::ctr, "aria-256-ctr"},
    {crypt_algorithm_t::aria256, crypt_mode_t::ecb, "aria-256-ecb"},
    {crypt_algorithm_t::aria256, crypt_mode_t::gcm, "aria-256-gcm"},
    {crypt_algorithm_t::aria256, crypt_mode_t::ofb, "aria-256-ofb"},
    {crypt_algorithm_t::aria256, crypt_mode_t::ccm8, "aria-256-ccm"},

    {crypt_algorithm_t::blowfish, crypt_mode_t::cbc, "bf-cbc"},
    {crypt_algorithm_t::blowfish, crypt_mode_t::cfb, "bf-cfb"},
    //{ crypt_algorithm_t::blowfish, crypt_mode_t::ctr, "bf-ctr" },
    {crypt_algorithm_t::blowfish, crypt_mode_t::ecb, "bf-ecb"},
    {crypt_algorithm_t::blowfish, crypt_mode_t::ofb, "bf-ofb"},

    {crypt_algorithm_t::camellia128, crypt_mode_t::cbc, "camellia-128-cbc"},
    //{ crypt_algorithm_t::camellia128, crypt_mode_t::ccm, "camellia-128-ccm" },
    {crypt_algorithm_t::camellia128, crypt_mode_t::cfb, "camellia-128-cfb"},
    {crypt_algorithm_t::camellia128, crypt_mode_t::cfb1, "camellia-128-cfb1"},
    {crypt_algorithm_t::camellia128, crypt_mode_t::cfb8, "camellia-128-cfb8"},
    {crypt_algorithm_t::camellia128, crypt_mode_t::ctr, "camellia-128-ctr"},
    {crypt_algorithm_t::camellia128, crypt_mode_t::ecb, "camellia-128-ecb"},
    {crypt_algorithm_t::camellia128, crypt_mode_t::gcm, "camellia-128-gcm"},
    {crypt_algorithm_t::camellia128, crypt_mode_t::ofb, "camellia-128-ofb"},

    {crypt_algorithm_t::camellia192, crypt_mode_t::cbc, "camellia-192-cbc"},
    // {crypt_algorithm_t::camellia192, crypt_mode_t::ccm, "camellia-192-ccm"},
    {crypt_algorithm_t::camellia192, crypt_mode_t::cfb, "camellia-192-cfb"},
    {crypt_algorithm_t::camellia192, crypt_mode_t::cfb1, "camellia-192-cfb1"},
    {crypt_algorithm_t::camellia192, crypt_mode_t::cfb8, "camellia-192-cfb8"},
    {crypt_algorithm_t::camellia192, crypt_mode_t::ctr, "camellia-192-ctr"},
    {crypt_algorithm_t::camellia192, crypt_mode_t::ecb, "camellia-192-ecb"},
    {crypt_algorithm_t::camellia192, crypt_mode_t::gcm, "camellia-192-gcm"},
    {crypt_algorithm_t::camellia192, crypt_mode_t::ofb, "camellia-192-ofb"},

    {crypt_algorithm_t::camellia256, crypt_mode_t::cbc, "camellia-256-cbc"},
    //{ crypt_algorithm_t::camellia256, crypt_mode_t::ccm, "camellia-256-ccm" },
    {crypt_algorithm_t::camellia256, crypt_mode_t::cfb, "camellia-256-cfb"},
    {crypt_algorithm_t::camellia256, crypt_mode_t::cfb1, "camellia-256-cfb1"},
    {crypt_algorithm_t::camellia256, crypt_mode_t::cfb8, "camellia-256-cfb8"},
    {crypt_algorithm_t::camellia256, crypt_mode_t::ctr, "camellia-256-ctr"},
    {crypt_algorithm_t::camellia256, crypt_mode_t::ecb, "camellia-256-ecb"},
    {crypt_algorithm_t::camellia256, crypt_mode_t::gcm, "camellia-256-gcm"},
    {crypt_algorithm_t::camellia256, crypt_mode_t::ofb, "camellia-256-ofb"},

    {crypt_algorithm_t::cast, crypt_mode_t::cbc, "cast5-cbc"},
    {crypt_algorithm_t::cast, crypt_mode_t::cfb, "cast5-cfb"},
    {crypt_algorithm_t::cast, crypt_mode_t::ecb, "cast5-ecb"},
    {crypt_algorithm_t::cast, crypt_mode_t::ofb, "cast5-ofb"},

    {crypt_algorithm_t::idea, crypt_mode_t::cbc, "idea-cbc"},
    {crypt_algorithm_t::idea, crypt_mode_t::cfb, "idea-cfb"},
    {crypt_algorithm_t::idea, crypt_mode_t::ecb, "idea-ecb"},
    {crypt_algorithm_t::idea, crypt_mode_t::ofb, "idea-ofb"},

    {crypt_algorithm_t::rc2, crypt_mode_t::cbc, "rc2-cbc"},
    {crypt_algorithm_t::rc2, crypt_mode_t::cfb, "rc2-cfb"},
    {crypt_algorithm_t::rc2, crypt_mode_t::ecb, "rc2-ecb"},
    {crypt_algorithm_t::rc2, crypt_mode_t::ofb, "rc2-ofb"},

    {crypt_algorithm_t::rc5, crypt_mode_t::cbc, "rc5-cbc"},
    {crypt_algorithm_t::rc5, crypt_mode_t::cfb, "rc5-cfb"},
    {crypt_algorithm_t::rc5, crypt_mode_t::ecb, "rc5-ecb"},
    {crypt_algorithm_t::rc5, crypt_mode_t::ofb, "rc5-ofb"},

    {crypt_algorithm_t::sm4, crypt_mode_t::cbc, "sm4-cbc"},
    {crypt_algorithm_t::sm4, crypt_mode_t::cfb, "sm4-cfb"},
    {crypt_algorithm_t::sm4, crypt_mode_t::ecb, "sm4-ecb"},
    {crypt_algorithm_t::sm4, crypt_mode_t::ofb, "sm4-ofb"},
    {crypt_algorithm_t::sm4, crypt_mode_t::ctr, "sm4-ctr"},

    {crypt_algorithm_t::seed, crypt_mode_t::cbc, "seed-cbc"},
    {crypt_algorithm_t::seed, crypt_mode_t::cfb, "seed-cfb"},
    {crypt_algorithm_t::seed, crypt_mode_t::ecb, "seed-ecb"},
    {crypt_algorithm_t::seed, crypt_mode_t::ofb, "seed-ofb"},

    {crypt_algorithm_t::rc4, crypt_mode_t::mode_cipher, "rc4"},
    {crypt_algorithm_t::chacha20, crypt_mode_t::mode_cipher, "chacha20"},
    {crypt_algorithm_t::chacha20, crypt_mode_t::mode_poly1305, "chacha20-poly1305"},
};

const size_t sizeof_evp_cipher_methods = RTL_NUMBER_OF(evp_cipher_methods);

crypt_algorithm_t typeof_alg(const hint_cipher_t* hint) {
    crypt_algorithm_t ret_value = crypt_algorithm_t::crypt_alg_unknown;
    if (hint) {
        ret_value = hint->algorithm;
    }
    return ret_value;
}

crypt_mode_t typeof_mode(const hint_cipher_t* hint) {
    crypt_mode_t ret_value = crypt_mode_t::mode_unknown;
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

const openssl_evp_cipher_method_older_t aes_wrap_methods[] = {
    {EVP_aes_128_wrap(), {crypt_algorithm_t::aes128, crypt_mode_t::wrap, "aes-128-wrap"}},
    {EVP_aes_192_wrap(), {crypt_algorithm_t::aes192, crypt_mode_t::wrap, "aes-192-wrap"}},
    {EVP_aes_256_wrap(), {crypt_algorithm_t::aes256, crypt_mode_t::wrap, "aes-256-wrap"}},
};

const size_t sizeof_aes_wrap_methods = RTL_NUMBER_OF(aes_wrap_methods);

}  // namespace crypto
}  // namespace hotplace
