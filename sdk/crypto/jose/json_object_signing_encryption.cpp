/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 7515 JSON Web Signature (JWS)
 *  RFC 7516 JSON Web Encryption (JWE)
 *  RFC 7517 JSON Web Key (JWK)
 *  RFC 7518 JSON Web Algorithms (JWA)
 *  RFC 7520 Examples of Protecting Content Using JSON Object Signing and Encryption (JOSE)
 *  RFC 8037 CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)
 *
 * Revision History
 * Date         Name                Description
 */

#include <iostream>
#include <sdk/base.hpp>
#include <sdk/base/basic/base64.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/crypto/jose/json_object_encryption.hpp>
#include <sdk/crypto/jose/json_object_signing.hpp>
#include <sdk/crypto/jose/json_object_signing_encryption.hpp>
#include <sdk/crypto/jose/json_web_key.hpp>
#include <sdk/io/basic/json.hpp>
#include <sdk/io/basic/zlib.hpp>
#include <sdk/io/string/string.hpp>

namespace hotplace {
using namespace io;
namespace crypto {

json_object_signing_encryption::json_object_signing_encryption() {
    // do nothing
}

json_object_signing_encryption::~json_object_signing_encryption() {
    // do nothing
}

return_t json_object_signing_encryption::open(jose_context_t** handle, crypto_key* crypto_key) {
    return_t ret = errorcode_t::success;
    jose_context_t* context = nullptr;

    __try2 {
        if (nullptr == handle || nullptr == crypto_key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try_new_catch(context, new jose_context_t, ret, __leave2);

        context->key = crypto_key;

        crypto_key->addref();

        *handle = context;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (context) {
                delete context;
            }
        }
    }
    return ret;
}

return_t json_object_signing_encryption::close(jose_context_t* handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        clear_context(handle);

        if (handle->key) {
            handle->key->release();
        }
        delete handle;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t json_object_signing_encryption::setoption(jose_context_t* handle, uint32 flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        handle->flags = flags;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t json_object_signing_encryption::encrypt(jose_context_t* handle, jwe_t enc, jwa_t alg, binary_t const& input, std::string& output,
                                                 jose_serialization_t type) {
    json_object_encryption jwe;

    return jwe.encrypt(handle, enc, alg, input, output, type);
}

return_t json_object_signing_encryption::encrypt(jose_context_t* handle, jwe_t enc, std::list<jwa_t> algs, binary_t const& input, std::string& output,
                                                 jose_serialization_t type) {
    json_object_encryption jwe;

    return jwe.encrypt(handle, enc, algs, input, output, type);
}

return_t json_object_signing_encryption::decrypt(jose_context_t* handle, std::string const& input, binary_t& output, bool& result) {
    json_object_encryption jwe;

    return jwe.decrypt(handle, input, output, result);
}

return_t json_object_signing_encryption::sign(jose_context_t* context, jws_t method, std::string const& input, std::string& output, jose_serialization_t type) {
    json_object_signing jws;

    return jws.sign(context, method, input, output, type);
}

return_t json_object_signing_encryption::sign(jose_context_t* context, std::list<jws_t> const& methods, std::string const& input, std::string& output,
                                              jose_serialization_t type) {
    json_object_signing jws;

    return jws.sign(context, methods, input, output, type);
}

return_t json_object_signing_encryption::sign(jose_context_t* context, std::string const& protected_header, std::string const& input, std::string& output,
                                              jose_serialization_t type) {
    json_object_signing jws;

    return jws.sign(context, protected_header, input, output, type);
}

return_t json_object_signing_encryption::sign(jose_context_t* context, std::list<std::string> const& headers, std::string const& input, std::string& output,
                                              jose_serialization_t type) {
    json_object_signing jws;

    return jws.sign(context, headers, input, output, type);
}

return_t json_object_signing_encryption::verify(jose_context_t* context, std::string const& input, bool& result) {
    json_object_signing jws;

    return jws.verify(context, input, result);
}

return_t json_object_signing_encryption::clear_context(jose_context_t* handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        for (jose_encryptions_map_t::iterator iter = handle->encryptions.begin(); iter != handle->encryptions.end(); iter++) {
            jose_encryption_t& item = iter->second;

            for (jose_recipients_t::iterator rit = item.recipients.begin(); rit != item.recipients.end(); rit++) {
                jose_recipient_t& recipient = rit->second;

                EVP_PKEY_free((EVP_PKEY*)recipient.epk);
            }
        }

        handle->protected_header.clear();
        handle->encryptions.clear();
        handle->signs.clear();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
