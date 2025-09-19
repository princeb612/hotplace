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

#ifndef __HOTPLACE_SDK_NET_HTTP_AUTH_BEARERCREDENTIALS__
#define __HOTPLACE_SDK_NET_HTTP_AUTH_BEARERCREDENTIALS__

#include <hotplace/sdk/base/system/critical_section.hpp>
#include <map>
#include <string>

namespace hotplace {
namespace net {

class http_authentication_provider;
class bearer_credentials {
   public:
    bearer_credentials();

    bearer_credentials& add(const std::string& client_id, const std::string& access_token);
    bool verify(http_authentication_provider* provider, const std::string& token);

   private:
    critical_section _lock;
    std::map<std::string, std::string> _bearer_credential;  // map(access_token, client_id)
};

}  // namespace net
}  // namespace hotplace

#endif
