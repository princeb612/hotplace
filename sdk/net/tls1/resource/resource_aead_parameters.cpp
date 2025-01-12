/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>

namespace hotplace {
namespace net {

#define ENDOF_DATA

define_tls_variable(aead_alg_code) = {
    {1, "AEAD_AES_128_GCM", ENDOF_DATA},
    {2, "AEAD_AES_256_GCM", ENDOF_DATA},
    {3, "AEAD_AES_128_CCM", ENDOF_DATA},
    {4, "AEAD_AES_256_CCM", ENDOF_DATA},
    {5, "AEAD_AES_128_GCM_8", ENDOF_DATA},
    {6, "AEAD_AES_256_GCM_8", ENDOF_DATA},
    {7, "AEAD_AES_128_GCM_12", ENDOF_DATA},
    {8, "AEAD_AES_256_GCM_12", ENDOF_DATA},
    {9, "AEAD_AES_128_CCM_SHORT", ENDOF_DATA},
    {10, "AEAD_AES_256_CCM_SHORT", ENDOF_DATA},
    {11, "AEAD_AES_128_CCM_SHORT_8", ENDOF_DATA},
    {12, "AEAD_AES_256_CCM_SHORT_8", ENDOF_DATA},
    {13, "AEAD_AES_128_CCM_SHORT_12", ENDOF_DATA},
    {14, "AEAD_AES_256_CCM_SHORT_12", ENDOF_DATA},
    {15, "AEAD_AES_SIV_CMAC_256", ENDOF_DATA},
    {16, "AEAD_AES_SIV_CMAC_384", ENDOF_DATA},
    {17, "AEAD_AES_SIV_CMAC_512", ENDOF_DATA},
    {18, "AEAD_AES_128_CCM_8", ENDOF_DATA},
    {19, "AEAD_AES_256_CCM_8", ENDOF_DATA},
    {20, "AEAD_AES_128_OCB_TAGLEN128", ENDOF_DATA},
    {21, "AEAD_AES_128_OCB_TAGLEN96", ENDOF_DATA},
    {22, "AEAD_AES_128_OCB_TAGLEN64", ENDOF_DATA},
    {23, "AEAD_AES_192_OCB_TAGLEN128", ENDOF_DATA},
    {24, "AEAD_AES_192_OCB_TAGLEN96", ENDOF_DATA},
    {25, "AEAD_AES_192_OCB_TAGLEN64", ENDOF_DATA},
    {26, "AEAD_AES_256_OCB_TAGLEN128", ENDOF_DATA},
    {27, "AEAD_AES_256_OCB_TAGLEN96", ENDOF_DATA},
    {28, "AEAD_AES_256_OCB_TAGLEN64", ENDOF_DATA},
    {29, "AEAD_CHACHA20_POLY1305", ENDOF_DATA},
    {30, "AEAD_AES_128_GCM_SIV", ENDOF_DATA},
    {31, "AEAD_AES_256_GCM_SIV", ENDOF_DATA},
    {32, "AEAD_AEGIS128L", ENDOF_DATA},
    {33, "AEAD_AEGIS256", ENDOF_DATA},
};
define_tls_sizeof_variable(aead_alg_code);

}  // namespace net
}  // namespace hotplace
