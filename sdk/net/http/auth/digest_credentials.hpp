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

#ifndef __HOTPLACE_SDK_NET_HTTP_AUTH_DIGESTCREDENTIALS__
#define __HOTPLACE_SDK_NET_HTTP_AUTH_DIGESTCREDENTIALS__

#include <map>
#include <sdk/base/basic/keyvalue.hpp>
#include <sdk/net/types.hpp>
#include <string>

namespace hotplace {
namespace net {

class digest_credentials {
   public:
    digest_credentials();

    digest_credentials& add(const std::string& userid, const std::string& password);
    digest_credentials& add(const std::string& realm, const std::string& algorithm, const std::string& userid, const std::string& password);
    bool verify(http_authentication_provider* provider, skey_value& kv);

   private:
    critical_section _lock;
    std::map<std::string, std::string> _digest_access_credential;  // map(userid, password)
    std::map<std::string, std::string> _digest_access_userhash;    // map(_H(userid:realm), userid)
};

}  // namespace net
}  // namespace hotplace

#endif
