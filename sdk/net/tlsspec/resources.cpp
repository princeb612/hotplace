/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tlsspec/tls.hpp>
#include <sdk/net/tlsspec/tls_advisor.hpp>

namespace hotplace {
namespace net {

const tls_alg_info_t tls_alg_info[] = {
    {
        0x1301,  // TLS_AES_128_GCM_SHA256
        aes128,
        gcm,
        16,
        sha2_256,
    },
    {
        0x1302,  // TLS_AES_256_GCM_SHA384
        aes256,
        gcm,
        16,
        sha2_384,
    },
    {
        0x1303,  // TLS_CHACHA20_POLY1305_SHA256
        chacha20,
        crypt_aead,
        16,
        sha2_256,
    },
    {
        0x1304,  // TLS_AES_128_CCM_SHA256, Tag 16
        aes128,
        ccm,
        16,
        sha2_256,
    },
    {
        0x1305,  // TLS_AES_128_CCM_8_SHA256, Tag 8
        aes128,
        ccm,
        8,
        sha2_256,
    },
    {
        0xc013,  // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        aes128,
        cbc,
        0,
        sha1,
        sha2_256,
    },
};

const size_t sizeof_tls_alg_info = RTL_NUMBER_OF(tls_alg_info);

}  // namespace net
}  // namespace hotplace
