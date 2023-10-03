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

return_t cbor_object_signing::sign (cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output, std::string& kid)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    cbor_object_signing_encryption cose;
    openssl_sign sign;

    __try2
    {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        cose.reset (handle);

        crypt_sig_t sig = advisor->cose_sigof (method);
        EVP_PKEY* pkey = key->select (kid, sig);

        ret = sign.sign (pkey, sig, input, output);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        switch (method) {
            case cose_alg_t::cose_hs256_64:
                output.resize (64 >> 3);
                break;
            default:
                break;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing::verify (cose_context_t* handle, crypto_key* key, const char* kid, cose_alg_t method, binary_t const& input, binary_t const& output, bool& result)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    openssl_sign sign;

    __try2
    {
        result = false;

        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypt_sig_t sig = advisor->cose_sigof (method);

        EVP_PKEY* pkey = nullptr;
        if (nullptr == kid) {
            pkey = key->select (sig);
        } else {
            pkey = key->find (kid, sig);
        }

        if (cose_alg_t::cose_hs256_64 == method) {
            binary_t signature;
            ret = sign.sign (pkey, sig, input, signature);
            signature.resize (64 >> 3);
            if (signature == output) {
                result = true;
            }
        } else {
            ret = sign.verify (pkey, sig, input, output);
            if (errorcode_t::success == ret) {
                result = true;
            }
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
