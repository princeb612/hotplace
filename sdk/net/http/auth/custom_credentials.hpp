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
#include <sdk/net/http/http_authentication_provider.hpp>
#include <string>

namespace hotplace {
namespace net {

class custom_credentials {
   public:
    custom_credentials();

    custom_credentials& add(const std::string& username, const std::string& password);
    bool verify(http_authenticate_provider* provider, const std::string& username, const std::string& password);

   private:
    critical_section _lock;
    std::map<std::string, std::string> _custom_credential;
};

}  // namespace net
}  // namespace hotplace

#endif
