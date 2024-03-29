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

#ifndef __HOTPLACE_SDK_NET_HTTP_CUSTOM_CREDENTIALS__
#define __HOTPLACE_SDK_NET_HTTP_CUSTOM_CREDENTIALS__

#include <map>
#include <sdk/base.hpp>
#include <sdk/io/basic/keyvalue.hpp>
#include <string>

namespace hotplace {
namespace net {

class http_authenticate_provider;
class custom_credentials {
   public:
    custom_credentials();

    custom_credentials& add(std::string const& username, std::string const& password);
    bool verify(http_authenticate_provider* provider, std::string const& username, std::string const& password);

   private:
    critical_section _lock;
    std::map<std::string, std::string> _custom_credential;
};

}  // namespace net
}  // namespace hotplace

#endif
