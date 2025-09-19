/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_AUTHENTICODE_SDK__
#define __HOTPLACE_SDK_CRYPTO_AUTHENTICODE_SDK__

#include <hotplace/sdk/crypto/authenticode/types.hpp>

namespace hotplace {
namespace crypto {

return_t crl_distribution_point(X509* cert, std::set<std::string>& crls);
return_t pkcs7_digest_info(PKCS7* pkcs7_pointer, std::string& md, binary_t& digest);
return_t X509_NAME_to_string(X509_NAME* name, std::string& data);

}  // namespace crypto
}  // namespace hotplace

#endif
