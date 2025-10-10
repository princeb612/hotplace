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
#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

return_t dump_pem(const EVP_PKEY* pkey, stream_t* stream) {
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

        dump_pem(pkey, out);

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

return_t dump_pem(const EVP_PKEY* pkey, BIO* out) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == pkey || nullptr == out) {
            __leave2;
        }

        int type = EVP_PKEY_id(pkey);

        if (EVP_PKEY_HMAC == type) {
            PEM_write_bio_PrivateKey(out, (EVP_PKEY*)pkey, nullptr, nullptr, 0, nullptr, nullptr);
        } else if (EVP_PKEY_RSA == type) {
            if (RSA_get0_d(EVP_PKEY_get0_RSA((EVP_PKEY*)pkey))) {
                PEM_write_bio_RSAPrivateKey(out, EVP_PKEY_get0_RSA((EVP_PKEY*)pkey), nullptr, nullptr, 0, nullptr, nullptr);
            }
            PEM_write_bio_RSAPublicKey(out, EVP_PKEY_get0_RSA((EVP_PKEY*)pkey));
        } else if (EVP_PKEY_EC == type) {
            EC_KEY* ec_key = (EC_KEY*)EVP_PKEY_get0_EC_KEY((EVP_PKEY*)pkey);

            if (nullptr == ec_key) {
                ret = errorcode_t::bad_data;
                __leave2_trace(ret);
            }

            const BIGNUM* bn = EC_KEY_get0_private_key(ec_key);
            if (bn) {
                PEM_write_bio_ECPrivateKey(out, ec_key, nullptr, nullptr, 0, nullptr, nullptr);
            }
            PEM_write_bio_EC_PUBKEY(out, ec_key);  // same PEM_write_bio_PUBKEY
        } else if (EVP_PKEY_DH == type) {
            auto dh = EVP_PKEY_get0_DH((EVP_PKEY*)pkey);
            const BIGNUM* bn_priv = nullptr;
            DH_get0_key(dh, nullptr, &bn_priv);
            if (bn_priv) {
                PEM_write_bio_PrivateKey(out, (EVP_PKEY*)pkey, nullptr, nullptr, 0, nullptr, nullptr);
            }
            PEM_write_bio_Parameters(out, (EVP_PKEY*)pkey);
        } else if (EVP_PKEY_KEYMGMT == type) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
            crypto_keychain keychain;
            binary_t keydata;
            bool is_keypair = keychain.pkey_is_private(nullptr, pkey);
            keychain.pkey_encode(nullptr, pkey, keydata, is_keypair ? key_encoding_priv_pem : key_encoding_pub_pem);
            if (keydata.size()) {
                BIO_write(out, &keydata[0], keydata.size());
            }
#endif
        }
    }
    __finally2 {}

    return ret;
}

}  // namespace crypto
}  // namespace hotplace
