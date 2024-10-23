/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 8152 CBOR Object Signing and Encryption (COSE)
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_sign.hpp>
#include <sdk/crypto/cose/cbor_object_signing.hpp>
#include <sdk/crypto/cose/cbor_object_signing_encryption.hpp>
#include <sdk/crypto/cose/cose_composer.hpp>
#include <sdk/io/cbor/cbor.hpp>
#include <sdk/io/cbor/cbor_array.hpp>
#include <sdk/io/cbor/cbor_data.hpp>
#include <sdk/io/cbor/cbor_encode.hpp>
#include <sdk/io/cbor/cbor_map.hpp>
#include <sdk/io/cbor/cbor_publisher.hpp>
#include <sdk/io/cbor/cbor_reader.hpp>

namespace hotplace {
using namespace io;
namespace crypto {

cbor_object_signing::cbor_object_signing() {
    // do nothing
}

cbor_object_signing::~cbor_object_signing() {
    // do nothing
}

return_t cbor_object_signing::sign(cose_context_t* handle, crypto_key* key, cose_alg_t method, const binary_t& input, binary_t& output) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::list<cose_alg_t> methods;
        methods.push_back(method);

        ret = sign(handle, key, methods, input, output);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t cbor_object_signing::sign(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, const binary_t& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    cbor_object_signing_encryption cose;
    ret = cose.sign(handle, key, methods, input, output);
    return ret;
}

return_t cbor_object_signing::mac(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, const binary_t& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    cbor_object_signing_encryption cose;
    ret = cose.mac(handle, key, methods, input, output);
    return ret;
}

return_t cbor_object_signing::verify(cose_context_t* handle, crypto_key* key, const binary_t& input, bool& result) {
    return_t ret = errorcode_t::success;
    cbor_object_signing_encryption cose;
    __try2 {
        result = false;

        if (nullptr == handle || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        binary_t dummy;
        ret = cose.process(handle, key, input, dummy);
        if (errorcode_t::success == ret) {
            result = true;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
