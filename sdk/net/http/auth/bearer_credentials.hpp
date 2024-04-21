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

#ifndef __HOTPLACE_SDK_NET_HTTP_BEARER_CREDENTIALS__
#define __HOTPLACE_SDK_NET_HTTP_BEARER_CREDENTIALS__

#include <map>
#include <sdk/base.hpp>
#include <sdk/io.hpp>
#include <string>

namespace hotplace {
namespace net {

class http_authenticate_provider;
class bearer_credentials {
   public:
    bearer_credentials();

    bearer_credentials& add(std::string const& client_id, std::string const& access_token);
    bool verify(http_authenticate_provider* provider, std::string const& token);

   private:
    critical_section _lock;
    std::map<std::string, std::string> _bearer_credential;  // map(access_token, client_id)
};

}  // namespace net
}  // namespace hotplace

#endif
