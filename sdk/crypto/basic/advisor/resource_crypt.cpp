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

/* something wrong EVP_CIPHER_CTX_iv_length, EVP_CIPHER_CTX_block_size (openssl-1.1.1) */
const hint_blockcipher_t hint_blockciphers[] = {
    // 16 (128), 24 (192), 32 (256)

    {
        aes128,
        16,
        16,
        16,
        16,
    },
    {
        aes192,
        24,
        16,
        16,
        24,
    },
    {
        aes256,
        32,
        16,
        16,
        32,
    },
    {
        blowfish,
        16,
        8,
        8,
    },

    {
        aria128,
        16,
        16,
        16,
    },
    {
        aria192,
        24,
        16,
        16,
    },
    {
        aria256,
        32,
        16,
        16,
    },

    {
        camellia128,
        16,
        16,
        16,
    },
    {
        camellia192,
        24,
        16,
        16,
    },
    {
        camellia256,
        32,
        16,
        16,
    },

    {
        cast,
        16,
        8,
        8,
    },

    {
        idea,
        16,
        8,
        8,
    },

    {
        rc2,
        8,
        8,
        8,
    },

    {
        rc5,
        16,
        8,
        8,
    },

    {
        seed,
        16,
        16,
        16,
    },

    {
        sm4,
        16,
        16,
        16,
    },

    {
        rc4,
        0,
        12,
        0,
    },
    {
        chacha20,
        32,
        12,
        0,
    },
};

const size_t sizeof_hint_blockciphers = RTL_NUMBER_OF(hint_blockciphers);

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

const hint_cipher_t evp_cipher_methods[] = {
    // scheme contains algorithm and mode, repetition just for convenience

    {crypto_scheme_aes_128_cbc, aes128, cbc, "aes-128-cbc"},
    {crypto_scheme_aes_128_ccm, aes128, ccm, "aes-128-ccm"},
    {crypto_scheme_aes_128_cfb, aes128, cfb, "aes-128-cfb"},
    {crypto_scheme_aes_128_cfb1, aes128, cfb1, "aes-128-cfb1"},
    {crypto_scheme_aes_128_cfb8, aes128, cfb8, "aes-128-cfb8"},
    {crypto_scheme_aes_128_ctr, aes128, ctr, "aes-128-ctr"},
    {crypto_scheme_aes_128_ecb, aes128, ecb, "aes-128-ecb"},
    {crypto_scheme_aes_128_gcm, aes128, gcm, "aes-128-gcm"},
    {crypto_scheme_aes_128_ofb, aes128, ofb, "aes-128-ofb"},
    {crypto_scheme_aes_128_wrap, aes128, wrap, "aes-128-wrap"},

    {crypto_scheme_aes_192_cbc, aes192, cbc, "aes-192-cbc"},
    {crypto_scheme_aes_192_ccm, aes192, ccm, "aes-192-ccm"},
    {crypto_scheme_aes_192_cfb, aes192, cfb, "aes-192-cfb"},
    {crypto_scheme_aes_192_cfb1, aes192, cfb1, "aes-192-cfb1"},
    {crypto_scheme_aes_192_cfb8, aes192, cfb8, "aes-192-cfb8"},
    {crypto_scheme_aes_192_ctr, aes192, ctr, "aes-192-ctr"},
    {crypto_scheme_aes_192_ecb, aes192, ecb, "aes-192-ecb"},
    {crypto_scheme_aes_192_gcm, aes192, gcm, "aes-192-gcm"},
    {crypto_scheme_aes_192_ofb, aes192, ofb, "aes-192-ofb"},
    {crypto_scheme_aes_192_wrap, aes192, wrap, "aes-192-wrap"},

    {crypto_scheme_aes_256_cbc, aes256, cbc, "aes-256-cbc"},
    {crypto_scheme_aes_256_ccm, aes256, ccm, "aes-256-ccm"},
    {crypto_scheme_aes_256_cfb, aes256, cfb, "aes-256-cfb"},
    {crypto_scheme_aes_256_cfb1, aes256, cfb1, "aes-256-cfb1"},
    {crypto_scheme_aes_256_cfb8, aes256, cfb8, "aes-256-cfb8"},
    {crypto_scheme_aes_256_ctr, aes256, ctr, "aes-256-ctr"},
    {crypto_scheme_aes_256_ecb, aes256, ecb, "aes-256-ecb"},
    {crypto_scheme_aes_256_gcm, aes256, gcm, "aes-256-gcm"},
    {crypto_scheme_aes_256_ofb, aes256, ofb, "aes-256-ofb"},
    {crypto_scheme_aes_256_wrap, aes256, wrap, "aes-256-wrap"},

    {crypto_scheme_aria_128_cbc, aria128, cbc, "aria-128-cbc"},
    {crypto_scheme_aria_128_ccm, aria128, ccm, "aria-128-ccm"},
    {crypto_scheme_aria_128_cfb, aria128, cfb, "aria-128-cfb"},
    {crypto_scheme_aria_128_cfb1, aria128, cfb1, "aria-128-cfb1"},
    {crypto_scheme_aria_128_cfb8, aria128, cfb8, "aria-128-cfb8"},
    {crypto_scheme_aria_128_ctr, aria128, ctr, "aria-128-ctr"},
    {crypto_scheme_aria_128_ecb, aria128, ecb, "aria-128-ecb"},
    {crypto_scheme_aria_128_gcm, aria128, gcm, "aria-128-gcm"},
    {crypto_scheme_aria_128_ofb, aria128, ofb, "aria-128-ofb"},

    {crypto_scheme_aria_192_cbc, aria192, cbc, "aria-192-cbc"},
    {crypto_scheme_aria_192_ccm, aria192, ccm, "aria-192-ccm"},
    {crypto_scheme_aria_192_cfb, aria192, cfb, "aria-192-cfb"},
    {crypto_scheme_aria_192_cfb1, aria192, cfb1, "aria-192-cfb1"},
    {crypto_scheme_aria_192_cfb8, aria192, cfb8, "aria-192-cfb8"},
    {crypto_scheme_aria_192_ctr, aria192, ctr, "aria-192-ctr"},
    {crypto_scheme_aria_192_ecb, aria192, ecb, "aria-192-ecb"},
    {crypto_scheme_aria_192_gcm, aria192, gcm, "aria-192-gcm"},
    {crypto_scheme_aria_192_ofb, aria192, ofb, "aria-192-ofb"},

    {crypto_scheme_aria_256_cbc, aria256, cbc, "aria-256-cbc"},
    {crypto_scheme_aria_256_ccm, aria256, ccm, "aria-256-ccm"},
    {crypto_scheme_aria_256_cfb, aria256, cfb, "aria-256-cfb"},
    {crypto_scheme_aria_256_cfb1, aria256, cfb1, "aria-256-cfb1"},
    {crypto_scheme_aria_256_cfb8, aria256, cfb8, "aria-256-cfb8"},
    {crypto_scheme_aria_256_ctr, aria256, ctr, "aria-256-ctr"},
    {crypto_scheme_aria_256_ecb, aria256, ecb, "aria-256-ecb"},
    {crypto_scheme_aria_256_gcm, aria256, gcm, "aria-256-gcm"},
    {crypto_scheme_aria_256_ofb, aria256, ofb, "aria-256-ofb"},

    {crypto_scheme_bf_cbc, blowfish, cbc, "bf-cbc"},
    {crypto_scheme_bf_cfb, blowfish, cfb, "bf-cfb"},
    {crypto_scheme_bf_ecb, blowfish, ecb, "bf-ecb"},
    {crypto_scheme_bf_ofb, blowfish, ofb, "bf-ofb"},

    {crypto_scheme_camellia_128_cbc, camellia128, cbc, "camellia-128-cbc"},
    {crypto_scheme_camellia_128_cfb, camellia128, cfb, "camellia-128-cfb"},
    {crypto_scheme_camellia_128_cfb1, camellia128, cfb1, "camellia-128-cfb1"},
    {crypto_scheme_camellia_128_cfb8, camellia128, cfb8, "camellia-128-cfb8"},
    {crypto_scheme_camellia_128_ctr, camellia128, ctr, "camellia-128-ctr"},
    {crypto_scheme_camellia_128_ecb, camellia128, ecb, "camellia-128-ecb"},
    {crypto_scheme_camellia_128_gcm, camellia128, gcm, "camellia-128-gcm"},
    {crypto_scheme_camellia_128_ofb, camellia128, ofb, "camellia-128-ofb"},

    {crypto_scheme_camellia_192_cbc, camellia192, cbc, "camellia-192-cbc"},
    {crypto_scheme_camellia_192_cfb, camellia192, cfb, "camellia-192-cfb"},
    {crypto_scheme_camellia_192_cfb1, camellia192, cfb1, "camellia-192-cfb1"},
    {crypto_scheme_camellia_192_cfb8, camellia192, cfb8, "camellia-192-cfb8"},
    {crypto_scheme_camellia_192_ctr, camellia192, ctr, "camellia-192-ctr"},
    {crypto_scheme_camellia_192_ecb, camellia192, ecb, "camellia-192-ecb"},
    {crypto_scheme_camellia_192_gcm, camellia192, gcm, "camellia-192-gcm"},
    {crypto_scheme_camellia_192_ofb, camellia192, ofb, "camellia-192-ofb"},

    {crypto_scheme_camellia_256_cbc, camellia256, cbc, "camellia-256-cbc"},
    {crypto_scheme_camellia_256_cfb, camellia256, cfb, "camellia-256-cfb"},
    {crypto_scheme_camellia_256_cfb1, camellia256, cfb1, "camellia-256-cfb1"},
    {crypto_scheme_camellia_256_cfb8, camellia256, cfb8, "camellia-256-cfb8"},
    {crypto_scheme_camellia_256_ctr, camellia256, ctr, "camellia-256-ctr"},
    {crypto_scheme_camellia_256_ecb, camellia256, ecb, "camellia-256-ecb"},
    {crypto_scheme_camellia_256_gcm, camellia256, gcm, "camellia-256-gcm"},
    {crypto_scheme_camellia_256_ofb, camellia256, ofb, "camellia-256-ofb"},

    {crypto_scheme_cast5_cbc, cast, cbc, "cast5-cbc"},
    {crypto_scheme_cast5_cfb, cast, cfb, "cast5-cfb"},
    {crypto_scheme_cast5_ecb, cast, ecb, "cast5-ecb"},
    {crypto_scheme_cast5_ofb, cast, ofb, "cast5-ofb"},

    {crypto_scheme_idea_cbc, idea, cbc, "idea-cbc"},
    {crypto_scheme_idea_cfb, idea, cfb, "idea-cfb"},
    {crypto_scheme_idea_ecb, idea, ecb, "idea-ecb"},
    {crypto_scheme_idea_ofb, idea, ofb, "idea-ofb"},

    {crypto_scheme_rc2_cbc, rc2, cbc, "rc2-cbc"},
    {crypto_scheme_rc2_cfb, rc2, cfb, "rc2-cfb"},
    {crypto_scheme_rc2_ecb, rc2, ecb, "rc2-ecb"},
    {crypto_scheme_rc2_ofb, rc2, ofb, "rc2-ofb"},

    {crypto_scheme_rc5_cbc, rc5, cbc, "rc5-cbc"},
    {crypto_scheme_rc5_cfb, rc5, cfb, "rc5-cfb"},
    {crypto_scheme_rc5_ecb, rc5, ecb, "rc5-ecb"},
    {crypto_scheme_rc5_ofb, rc5, ofb, "rc5-ofb"},

    {crypto_scheme_sm4_cbc, sm4, cbc, "sm4-cbc"},
    {crypto_scheme_sm4_cfb, sm4, cfb, "sm4-cfb"},
    {crypto_scheme_sm4_ecb, sm4, ecb, "sm4-ecb"},
    {crypto_scheme_sm4_ofb, sm4, ofb, "sm4-ofb"},
    {crypto_scheme_sm4_ctr, sm4, ctr, "sm4-ctr"},

    {crypto_scheme_seed_cbc, seed, cbc, "seed-cbc"},
    {crypto_scheme_seed_cfb, seed, cfb, "seed-cfb"},
    {crypto_scheme_seed_ecb, seed, ecb, "seed-ecb"},
    {crypto_scheme_seed_ofb, seed, ofb, "seed-ofb"},

    {crypto_scheme_rc4, rc4, mode_cipher, "rc4"},
    {crypto_scheme_chacha20, chacha20, mode_chacha20, "chacha20"},
    {crypto_scheme_chacha20_poly1305, chacha20, mode_poly1305, "chacha20-poly1305"},

    // SET_L 3, SET_IVLEN=15-L=12, AEAD_SET_TAG 16 or 8
    {crypto_scheme_tls_aes_128_gcm, aes128, gcm, "aes-128-gcm", 15 - 3, 16},
    {crypto_scheme_tls_aes_256_gcm, aes256, gcm, "aes-256-gcm", 15 - 3, 16},
    {crypto_scheme_tls_aes_128_ccm, aes128, ccm, "aes-128-ccm", 15 - 3, 16},
    {crypto_scheme_tls_aes_256_ccm, aes256, ccm, "aes-256-ccm", 15 - 3, 16},
    {crypto_scheme_tls_aes_128_ccm_8, aes128, ccm, "aes-128-ccm", 15 - 3, 8},
    {crypto_scheme_tls_aes_256_ccm_8, aes256, ccm, "aes-256-ccm", 15 - 3, 8},
    {crypto_scheme_tls_chacha20_poly1305, chacha20, mode_poly1305, "chacha20-poly1305", 15 - 3, 16},
    {crypto_scheme_tls_aria_128_gcm, aria128, gcm, "aria-128-gcm", 15 - 3, 16},
    {crypto_scheme_tls_aria_256_gcm, aria256, gcm, "aria-256-gcm", 15 - 3, 16},
    {crypto_scheme_tls_aria_128_ccm, aria128, ccm, "aria-128-ccm", 15 - 3, 16},
    {crypto_scheme_tls_aria_256_ccm, aria256, ccm, "aria-256-ccm", 15 - 3, 16},
    {crypto_scheme_tls_camellia_128_gcm, camellia128, gcm, "camellia-128-gcm", 15 - 3, 16},
    {crypto_scheme_tls_camellia_256_gcm, camellia256, gcm, "camellia-256-gcm", 15 - 3, 16},
};

const size_t sizeof_evp_cipher_methods = RTL_NUMBER_OF(evp_cipher_methods);

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

const openssl_evp_cipher_method_older_t aes_wrap_methods[] = {
    {EVP_aes_128_wrap(), {crypto_scheme_aes_128_wrap, aes128, wrap, "aes-128-wrap"}},
    {EVP_aes_192_wrap(), {crypto_scheme_aes_192_wrap, aes192, wrap, "aes-192-wrap"}},
    {EVP_aes_256_wrap(), {crypto_scheme_aes_256_wrap, aes256, wrap, "aes-256-wrap"}},
};

const size_t sizeof_aes_wrap_methods = RTL_NUMBER_OF(aes_wrap_methods);

}  // namespace crypto
}  // namespace hotplace
