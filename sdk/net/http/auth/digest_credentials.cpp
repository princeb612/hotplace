/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base.hpp>
#include <sdk/crypto.hpp>
#include <sdk/io.hpp>
#include <sdk/net/http/auth/digest_access_authentication_provider.hpp>
#include <sdk/net/http/auth/digest_credentials.hpp>
#include <sdk/net/http/auth/rfc2617_digest.hpp>

namespace hotplace {
using namespace crypto;
using namespace io;
namespace net {

digest_credentials::digest_credentials() {}

digest_credentials& digest_credentials::add(std::string const& username, std::string const& password) {
    critical_section_guard guard(_lock);
    _digest_access_credential.insert(std::make_pair(username, password));
    return *this;
}

digest_credentials& digest_credentials::add(std::string const& realm, std::string const& algorithm, std::string const& username, std::string const& password) {
    rfc2617_digest dgst;
    dgst.add(username).add(":").add(realm).digest(algorithm);

    critical_section_guard guard(_lock);
    _digest_access_credential.insert(std::make_pair(username, password));
    _digest_access_userhash.insert(std::make_pair(dgst.get(), username));
    return *this;
}

bool digest_credentials::verify(http_authenticate_provider* provider, key_value& kv) {
    bool ret = false;
    __try2 {
        digest_access_authentication_provider* digest_provider = dynamic_cast<digest_access_authentication_provider*>(provider);
        if (nullptr == digest_provider) {
            __leave2;
        }

        critical_section_guard guard(_lock);

        std::string username = kv.get("username");
        std::string password;
        if (digest_provider->get_userhash()) {
            std::map<std::string, std::string>::iterator iter_userhash = _digest_access_userhash.find(username);
            if (_digest_access_userhash.end() == iter_userhash) {
                __leave2;
            } else {
                kv.set("username", iter_userhash->second);
                password = _digest_access_credential[iter_userhash->second];
                kv.set("password", password);
                ret = true;
            }
        } else {
            std::map<std::string, std::string>::iterator iter = _digest_access_credential.find(username);
            if (_digest_access_credential.end() == iter) {
                __leave2;
            } else {
                password = iter->second;
                kv.set("password", password);
                ret = true;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
