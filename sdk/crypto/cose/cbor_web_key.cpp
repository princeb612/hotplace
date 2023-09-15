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
#include <hotplace/sdk/crypto/basic/crypto_json_key.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/crypto/cose/cbor_web_key.hpp>
#include <hotplace/sdk/io/basic/base64.hpp>
#include <hotplace/sdk/io/basic/json.hpp>

namespace hotplace {
namespace crypto {

cbor_web_key::cbor_web_key () : crypto_json_key ()
{
    // do nothing
}

cbor_web_key::~cbor_web_key ()
{
    // do nothing
}

return_t cbor_web_key::load (crypto_key* crypto_key, const char* buffer, int flags)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

    }
    __finally2
    {
    }
    return ret;
}

return_t cbor_web_key::write (crypto_key* crypto_key, char* buf, size_t* buflen, int flags)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == crypto_key || nullptr == buflen) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t size_request = *buflen;
        std::string buffer;

        // crypto_key->for_each ();

    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

}
}  // namespace
