/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_BASIC_CREDENTIALS__
#define __HOTPLACE_SDK_NET_HTTP_BASIC_CREDENTIALS__

#include <map>
#include <sdk/base.hpp>
#include <sdk/io/basic/keyvalue.hpp>
#include <string>

namespace hotplace {
namespace net {

class http_authenticate_provider;
class basic_credentials {
   public:
    basic_credentials();

    basic_credentials& add(std::string const& username, std::string const& password);
    basic_credentials& add(std::string const& challenge);
    bool verify(http_authenticate_provider* provider, std::string const& credential);

   private:
    critical_section _lock;
    std::set<std::string> _basic_credential;  // set(base64_encode(concat(username, ":", password)))
};

}  // namespace net
}  // namespace hotplace

#endif
