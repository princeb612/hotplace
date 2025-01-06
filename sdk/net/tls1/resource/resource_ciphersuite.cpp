/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>

namespace hotplace {
namespace net {

const tls_cipher_suite_t tls_cipher_suites[] = {
    // TLS_{Key Exchange}_{Cipher}_{Mac}

    // RFC 8446 B.4.  Cipher Suites
    // RFC 5246 A.5.  The Cipher Suite

    // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    // --1 ----2 --3 ---------------4 -----5
    //
    // 1 protocol
    // 2 key agreement
    // 3 signature
    // 4 cipher + size + mode
    // 5 HMAC + size

    {
        0x1301,
        aes128,
        gcm,
        16,
        sha2_256,
    },
    {
        0x1302,
        aes256,
        gcm,
        16,
        sha2_384,
    },
    {
        0x1303,
        chacha20,
        crypt_aead,
        16,
        sha2_256,
    },
    {
        0x1304,
        aes128,
        ccm,
        16,
        sha2_256,
    },
    {
        0x1305,
        aes128,
        ccm,
        8,
        sha2_256,
    },
    {
        0xc013,
        aes128,
        cbc,
        0,
        sha1,
        sha2_256,
    },
};
const size_t sizeof_tls_cipher_suites = RTL_NUMBER_OF(tls_cipher_suites);

}  // namespace net
}  // namespace hotplace
