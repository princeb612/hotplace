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

#include <hotplace/sdk/crypto/cose/cbor_object_signing.hpp>

namespace hotplace {
namespace crypto {

cbor_object_signing::cbor_object_signing ()
{
    // do nothing
}

cbor_object_signing::~cbor_object_signing ()
{
    // do nothing
}

return_t cbor_object_signing::sign (crypto_key* key, crypt_sig_t method, binary_t const& input, binary_t& output)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing::sign (crypto_key* key, crypt_sig_t method, binary_t const& input, binary_t& output, std::string& kid)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing::verify (crypto_key* key, crypt_sig_t method, binary_t const& input, binary_t const& output, bool& result)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing::verify (crypto_key* key, const char* kid, crypt_sig_t method, binary_t const& input, binary_t const& output, bool& result)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

}
}  // namespace
