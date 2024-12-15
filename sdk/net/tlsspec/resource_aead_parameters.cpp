/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tlsspec/tls.hpp>
#include <sdk/net/tlsspec/tls_advisor.hpp>

namespace hotplace {
namespace net {

// keep single line
#define ENTRY(x, y) \
    { x, y }

define_tls_variable(aead_alg_desc) = {
    ENTRY(1, "AEAD_AES_128_GCM"),
    ENTRY(2, "AEAD_AES_256_GCM"),
    ENTRY(3, "AEAD_AES_128_CCM"),
    ENTRY(4, "AEAD_AES_256_CCM"),
    ENTRY(5, "AEAD_AES_128_GCM_8"),
    ENTRY(6, "AEAD_AES_256_GCM_8"),
    ENTRY(7, "AEAD_AES_128_GCM_12"),
    ENTRY(8, "AEAD_AES_256_GCM_12"),
    ENTRY(9, "AEAD_AES_128_CCM_SHORT"),
    ENTRY(10, "AEAD_AES_256_CCM_SHORT"),
    ENTRY(11, "AEAD_AES_128_CCM_SHORT_8"),
    ENTRY(12, "AEAD_AES_256_CCM_SHORT_8"),
    ENTRY(13, "AEAD_AES_128_CCM_SHORT_12"),
    ENTRY(14, "AEAD_AES_256_CCM_SHORT_12"),
    ENTRY(15, "AEAD_AES_SIV_CMAC_256"),
    ENTRY(16, "AEAD_AES_SIV_CMAC_384"),
    ENTRY(17, "AEAD_AES_SIV_CMAC_512"),
    ENTRY(18, "AEAD_AES_128_CCM_8"),
    ENTRY(19, "AEAD_AES_256_CCM_8"),
    ENTRY(20, "AEAD_AES_128_OCB_TAGLEN128"),
    ENTRY(21, "AEAD_AES_128_OCB_TAGLEN96"),
    ENTRY(22, "AEAD_AES_128_OCB_TAGLEN64"),
    ENTRY(23, "AEAD_AES_192_OCB_TAGLEN128"),
    ENTRY(24, "AEAD_AES_192_OCB_TAGLEN96"),
    ENTRY(25, "AEAD_AES_192_OCB_TAGLEN64"),
    ENTRY(26, "AEAD_AES_256_OCB_TAGLEN128"),
    ENTRY(27, "AEAD_AES_256_OCB_TAGLEN96"),
    ENTRY(28, "AEAD_AES_256_OCB_TAGLEN64"),
    ENTRY(29, "AEAD_CHACHA20_POLY1305"),
    ENTRY(30, "AEAD_AES_128_GCM_SIV"),
    ENTRY(31, "AEAD_AES_256_GCM_SIV"),
    ENTRY(32, "AEAD_AEGIS128L"),
    ENTRY(33, "AEAD_AEGIS256"),
};
define_tls_sizeof_variable(aead_alg_desc);

}  // namespace net
}  // namespace hotplace
