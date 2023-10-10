/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/io/cbor/cbor_data.hpp>
#include <hotplace/sdk/io/cbor/cbor_publisher.hpp>
#include <hotplace/sdk/io/string/string.hpp>

namespace hotplace {
using namespace io;
namespace crypto {

return_t write_pem(EVP_PKEY* pkey, stream_t* stream) {
    return_t ret = errorcode_t::success;
    BIO* out = nullptr;

    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            __leave2;
        }

        stream->clear();

        out = BIO_new(BIO_s_mem());
        if (nullptr == out) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        write_pem(pkey, out);

        binary_t buf;
        buf.resize(64);
        int len = 0;
        while (1) {
            len = BIO_read(out, &buf[0], buf.size());
            if (0 >= len) {
                break;
            }
            stream->write(&buf[0], len);
        }
    }
    __finally2 {
        if (out) {
            BIO_free_all(out);
        }
    }
    return ret;
}

return_t write_pem(EVP_PKEY* pkey, BIO* out) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == pkey || nullptr == out) {
            __leave2;
        }

        int type = EVP_PKEY_id(pkey);

        if (EVP_PKEY_HMAC == type) {
            PEM_write_bio_PrivateKey(out, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        } else if (EVP_PKEY_RSA == type) {
            if (RSA_get0_d(EVP_PKEY_get0_RSA(pkey))) {
                PEM_write_bio_RSAPrivateKey(out, EVP_PKEY_get0_RSA(pkey), nullptr, nullptr, 0, nullptr, nullptr);
            } else {
                PEM_write_bio_RSAPublicKey(out, EVP_PKEY_get0_RSA(pkey));
            }
        } else if (EVP_PKEY_EC == type) {
            EC_KEY* ec_key = (EC_KEY*)EVP_PKEY_get0_EC_KEY(pkey);

            if (nullptr == ec_key) {
                ret = errorcode_t::bad_data;
                throw ret;
                __leave2_trace(ret);
            }

            const BIGNUM* bn = EC_KEY_get0_private_key(ec_key);
            if (bn) {
                PEM_write_bio_ECPrivateKey(out, ec_key, nullptr, nullptr, 0, nullptr, nullptr);
            } else {
                PEM_write_bio_EC_PUBKEY(out, ec_key);  // same PEM_write_bio_PUBKEY
            }
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

}  // namespace crypto
}  // namespace hotplace
