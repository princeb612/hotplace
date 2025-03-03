/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/crypto_advisor.hpp>

namespace hotplace {
namespace crypto {

const hint_digest_t evp_md_methods[] = {
    {
        hash_algorithm_t::md4,
        "md4",
        128 >> 3,
    },
    {
        hash_algorithm_t::md5,
        "md5",
        128 >> 3,
    },

    {
        hash_algorithm_t::sha1,
        "sha1",
        160 >> 3,
    },

    {
        hash_algorithm_t::sha2_224,
        "sha224",
        224 >> 3,
    },
    {
        hash_algorithm_t::sha2_256,
        "sha256",
        256 >> 3,
    },
    {
        hash_algorithm_t::sha2_384,
        "sha384",
        384 >> 3,
    },
    {
        hash_algorithm_t::sha2_512,
        "sha512",
        512 >> 3,
    },
    {
        hash_algorithm_t::sha2_512_224,
        "sha2-512/224",
        224 >> 3,
    },
    {
        hash_algorithm_t::sha2_512_256,
        "sha2-512/256",
        256 >> 3,
    },

    {
        hash_algorithm_t::sha3_224,
        "sha3-224",
        224 >> 3,
    },
    {
        hash_algorithm_t::sha3_256,
        "sha3-256",
        256 >> 3,
    },
    {
        hash_algorithm_t::sha3_384,
        "sha3-384",
        384 >> 3,
    },
    {
        hash_algorithm_t::sha3_512,
        "sha3-512",
        512 >> 3,
    },

    {
        hash_algorithm_t::shake128,
        "shake128",
        256 >> 3,
    },
    {
        hash_algorithm_t::shake256,
        "shake256",
        512 >> 3,
    },

    {
        hash_algorithm_t::blake2b_512,
        "blake2b512",
        512 >> 3,
    },
    {
        hash_algorithm_t::blake2s_256,
        "blake2s256",
        256 >> 3,
    },

    {
        hash_algorithm_t::ripemd160,
        "ripemd160",
        160 >> 3,
    },

    {
        hash_algorithm_t::whirlpool,
        "whirlpool",
        512 >> 3,
    },
};

const size_t sizeof_evp_md_methods = RTL_NUMBER_OF(evp_md_methods);

hash_algorithm_t typeof_alg(const hint_digest_t *hint) {
    hash_algorithm_t ret_value = hash_algorithm_t::hash_alg_unknown;
    if (hint) {
        ret_value = hint->algorithm;
    }
    return ret_value;
}

const char *nameof_alg(const hint_digest_t *hint) {
    const char *ret_value = nullptr;
    if (hint) {
        ret_value = hint->fetchname;
    }
    return ret_value;
}

uint16 sizeof_digest(const hint_digest_t *hint) {
    uint16 ret_value = 0;
    if (hint) {
        ret_value = hint->digest_size;
    }
    return ret_value;
}

}  // namespace crypto
}  // namespace hotplace
