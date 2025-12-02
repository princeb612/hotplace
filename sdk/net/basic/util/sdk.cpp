/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>
#include <hotplace/sdk/io/system/socket.hpp>
#include <hotplace/sdk/net/basic/openssl/sdk.hpp>
#include <hotplace/sdk/net/basic/util/sdk.hpp>

namespace hotplace {
namespace net {

return_t generate_cookie_sockaddr(binary_t& cookie, const sockaddr* addr, socklen_t addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == addr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_advisor* advisor = crypto_advisor::get_instance();
        unsigned cookie_size = 16;
        binary_t key;
        advisor->get_cookie_secret(0, cookie_size, key);

        openssl_hash hash;
        hash_context_t* handle = nullptr;
        hash.open(&handle, "sha256", &key[0], key.size());
        hash.init(handle);
        hash.update(handle, (byte_t*)addr, addrlen);
        hash.finalize(handle, cookie);
        hash.close(handle);
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
