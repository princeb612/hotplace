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

#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>
#include <sdk/crypto/basic/types.hpp>
#include <set>
#include <string>

namespace hotplace {
namespace crypto {

return_t crl_distribution_point(X509* cert, std::set<std::string>& crls);
return_t pkcs7_digest_info(PKCS7* pkcs7_pointer, std::string& md, binary_t& digest);
return_t X509_NAME_to_string(X509_NAME* name, std::string& data);

}  // namespace crypto
}  // namespace hotplace

#endif
