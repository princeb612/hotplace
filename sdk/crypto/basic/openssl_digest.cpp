/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 2104 HMAC: Keyed-Hashing for Message Authentication
 *  RFC 4493 The AES-CMAC Algorithm
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

openssl_digest::openssl_digest() : openssl_hash() {}

return_t openssl_digest::digest(const char* alg, const binary_t& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    hash_context_t* handle = nullptr;

    __try2 {
        ret = open(&handle, alg);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        init(handle);
        update(handle, &input[0], input.size());
        finalize(handle, output);
    }
    __finally2 { close(handle); }

    return ret;
}

return_t openssl_digest::digest(hash_algorithm_t alg, const binary_t& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    hash_context_t* handle = nullptr;

    __try2 {
        ret = open(&handle, alg);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        init(handle);
        update(handle, &input[0], input.size());
        finalize(handle, output);
    }
    __finally2 { close(handle); }

    return ret;
}

return_t openssl_digest::digest(const char* alg, const basic_stream& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    hash_context_t* handle = nullptr;

    __try2 {
        ret = open(&handle, alg);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        init(handle);
        update(handle, input.data(), input.size());
        finalize(handle, output);
    }
    __finally2 { close(handle); }
    return ret;
}

return_t openssl_digest::digest(const char* alg, const basic_stream& input, std::string& hashstring, encoding_t encoding) {
    return_t ret = errorcode_t::success;
    binary_t output;
    ret = digest(alg, input, output);
    if (encoding_t::encoding_base64 == encoding) {
        hashstring = base64_encode(output, base64_encoding_t::base64_encoding);
    } else if (encoding_t::encoding_base64url == encoding) {
        hashstring = base64_encode(output, base64_encoding_t::base64url_encoding);
    } else {
        hashstring = base16_encode(output);
    }
    return ret;
}

return_t openssl_digest::digest(const char* alg, const std::string& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    hash_context_t* handle = nullptr;

    __try2 {
        ret = open(&handle, alg);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        init(handle);
        update(handle, (byte_t*)input.c_str(), input.size());
        finalize(handle, output);
    }
    __finally2 { close(handle); }
    return ret;
}

return_t openssl_digest::digest(const char* alg, const std::string& input, std::string& hashstring, encoding_t encoding) {
    return_t ret = errorcode_t::success;
    binary_t output;
    ret = digest(alg, input, output);
    if (encoding_t::encoding_base64 == encoding) {
        hashstring = base64_encode(output, base64_encoding_t::base64_encoding);
    } else if (encoding_t::encoding_base64 == encoding) {
        hashstring = base64_encode(output, base64_encoding_t::base64url_encoding);
    } else {
        hashstring = base16_encode(output);
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
