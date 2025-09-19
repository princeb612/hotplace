/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

define_tls_variable(aead_alg_code) = {
    {1, "AEAD_AES_128_GCM"},
    {2, "AEAD_AES_256_GCM"},
    {3, "AEAD_AES_128_CCM"},
    {4, "AEAD_AES_256_CCM"},
    {5, "AEAD_AES_128_GCM_8"},
    {6, "AEAD_AES_256_GCM_8"},
    {7, "AEAD_AES_128_GCM_12"},
    {8, "AEAD_AES_256_GCM_12"},
    {9, "AEAD_AES_128_CCM_SHORT"},
    {10, "AEAD_AES_256_CCM_SHORT"},
    {11, "AEAD_AES_128_CCM_SHORT_8"},
    {12, "AEAD_AES_256_CCM_SHORT_8"},
    {13, "AEAD_AES_128_CCM_SHORT_12"},
    {14, "AEAD_AES_256_CCM_SHORT_12"},
    {15, "AEAD_AES_SIV_CMAC_256"},
    {16, "AEAD_AES_SIV_CMAC_384"},
    {17, "AEAD_AES_SIV_CMAC_512"},
    {18, "AEAD_AES_128_CCM_8"},
    {19, "AEAD_AES_256_CCM_8"},
    {20, "AEAD_AES_128_OCB_TAGLEN128"},
    {21, "AEAD_AES_128_OCB_TAGLEN96"},
    {22, "AEAD_AES_128_OCB_TAGLEN64"},
    {23, "AEAD_AES_192_OCB_TAGLEN128"},
    {24, "AEAD_AES_192_OCB_TAGLEN96"},
    {25, "AEAD_AES_192_OCB_TAGLEN64"},
    {26, "AEAD_AES_256_OCB_TAGLEN128"},
    {27, "AEAD_AES_256_OCB_TAGLEN96"},
    {28, "AEAD_AES_256_OCB_TAGLEN64"},
    {29, "AEAD_CHACHA20_POLY1305"},
    {30, "AEAD_AES_128_GCM_SIV"},
    {31, "AEAD_AES_256_GCM_SIV"},
    {32, "AEAD_AEGIS128L"},
    {33, "AEAD_AEGIS256"},
};
define_tls_sizeof_variable(aead_alg_code);

}  // namespace net
}  // namespace hotplace
