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

#ifndef __HOTPLACE_SDK_NET_HTTP_DIGEST_CREDENTIALS__
#define __HOTPLACE_SDK_NET_HTTP_DIGEST_CREDENTIALS__

#include <map>
#include <sdk/base.hpp>
#include <sdk/io.hpp>
#include <string>

namespace hotplace {
namespace net {

class http_authenticate_provider;
using namespace io;
class digest_credentials {
   public:
    digest_credentials();

    digest_credentials& add(std::string const& userid, std::string const& password);
    digest_credentials& add(std::string const& realm, std::string const& algorithm, std::string const& userid, std::string const& password);
    bool verify(http_authenticate_provider* provider, key_value& kv);

   private:
    critical_section _lock;
    std::map<std::string, std::string> _digest_access_credential;  // map(userid, password)
    std::map<std::string, std::string> _digest_access_userhash;    // map(_H(userid:realm), userid)
};

}  // namespace net
}  // namespace hotplace

#endif
