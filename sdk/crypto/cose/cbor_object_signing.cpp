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

#include <hotplace/sdk/crypto/basic/openssl_sign.hpp>
#include <hotplace/sdk/crypto/cose/cbor_object_signing.hpp>
#include <hotplace/sdk/io/cbor/concise_binary_object_representation.hpp>

namespace hotplace {
using namespace io;
namespace crypto {

cbor_object_signing::cbor_object_signing ()
{
    // do nothing
}

cbor_object_signing::~cbor_object_signing ()
{
    // do nothing
}

return_t cbor_object_signing::sign (cose_context_t* handle, crypto_key* key, crypt_sig_t method, binary_t const& input, binary_t& output)
{
    return_t ret = errorcode_t::success;
    std::string kid;

    ret = sign (handle, key, method, input, output, kid);
    return ret;
}

return_t cbor_object_signing::sign (cose_context_t* handle, crypto_key* key, crypt_sig_t method, binary_t const& input, binary_t& output, std::string& kid)
{
    return_t ret = errorcode_t::success;
    cbor_object_signing_encryption cose;
    openssl_sign sign;

    __try2
    {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cose.reset (handle);

        EVP_PKEY* pkey = key->select (kid, method);

        ret = sign.sign (pkey, method, input, output);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        handle->kid = kid;
        handle->sig = method;
        handle->tag = cbor_tag_t::cose_tag_sign;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing::verify (cose_context_t* handle, crypto_key* key, crypt_sig_t method, binary_t const& input, binary_t const& output, bool& result)
{
    return_t ret = errorcode_t::success;

    ret = verify (handle, key, nullptr, method, input, output, result);
    return ret;
}

return_t cbor_object_signing::verify (cose_context_t* handle, crypto_key* key, const char* kid, crypt_sig_t method, binary_t const& input, binary_t const& output, bool& result)
{
    return_t ret = errorcode_t::success;
    openssl_sign sign;

    __try2
    {
        result = false;

        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        EVP_PKEY* pkey = nullptr;
        if (nullptr == kid) {
            pkey = key->select (method);
        } else {
            pkey = key->find (kid, method);
        }
        ret = sign.verify (pkey, method, input, output);
        if (errorcode_t::success == ret) {
            result = true;
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
