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

const openssl_evp_md_method_t evp_md_methods[] = {
    {
        hash_algorithm_t::md4,
        "md4",
    },
    {
        hash_algorithm_t::md5,
        "md5",
    },

    {
        hash_algorithm_t::sha1,
        "sha1",
    },

    {
        hash_algorithm_t::sha2_224,
        "sha224",
    },
    {
        hash_algorithm_t::sha2_256,
        "sha256",
    },
    {
        hash_algorithm_t::sha2_384,
        "sha384",
    },
    {
        hash_algorithm_t::sha2_512,
        "sha512",
    },
    {
        hash_algorithm_t::sha2_512_224,
        "sha2-512/224",
    },
    {
        hash_algorithm_t::sha2_512_256,
        "sha2-512/256",
    },

    {
        hash_algorithm_t::sha3_224,
        "sha3-224",
    },
    {
        hash_algorithm_t::sha3_256,
        "sha3-256",
    },
    {
        hash_algorithm_t::sha3_384,
        "sha3-384",
    },
    {
        hash_algorithm_t::sha3_512,
        "sha3-512",
    },

    {
        hash_algorithm_t::shake128,
        "shake128",
    },
    {
        hash_algorithm_t::shake256,
        "shake256",
    },

    {
        hash_algorithm_t::blake2b_512,
        "blake2b512",
    },
    {
        hash_algorithm_t::blake2s_256,
        "blake2s256",
    },

    {
        hash_algorithm_t::ripemd160,
        "ripemd160",
    },

    {
        hash_algorithm_t::whirlpool,
        "whirlpool",
    },
};

const size_t sizeof_evp_md_methods = RTL_NUMBER_OF(evp_md_methods);

}  // namespace crypto
}  // namespace hotplace
