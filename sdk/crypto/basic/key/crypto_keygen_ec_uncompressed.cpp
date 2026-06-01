/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keygen_ec_uncompressed.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keygen.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_keygen::add_ec_uncompressed(crypto_key* cryptokey, uint32 nid, const byte_t* pubkey, size_t pubsize, const byte_t* privkey, size_t privsize,
                                            keydesc&& desc) {
    return_t ret = errorcode_t::success;
    EC_KEY* eck = nullptr;
    int rc = 1;
    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        EVP_PKEY_ptr pkey(EVP_PKEY_new());
        if (nullptr == pkey.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        eck = EC_KEY_new_by_curve_name(nid);
        if (nullptr == eck) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // call both o2i_ECPublicKey and EC_KEY_set_private_key
        if (pubkey && pubsize) {
            o2i_ECPublicKey(/* inout */ &eck, &pubkey, t_narrow_cast(pubsize));
        }

        EC_KEY_ptr eckey(eck);
        eck = nullptr;  // eckey own eck

        if (privkey && privsize) {
            BN_ptr bn_priv(BN_bin2bn(privkey, t_narrow_cast(privsize), nullptr));

            rc = EC_KEY_set_private_key(eckey.get(), bn_priv.get());
            if (rc != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        }

        rc = EVP_PKEY_assign_EC_KEY(pkey.get(), eckey.get());
        if (rc < 1) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        eckey.release();  // pkey own eckey

        crypto_key_object key(pkey.get(), std::forward<keydesc>(desc));
        ret = cryptokey->add(std::move(key));
        if (errorcode_t::success != ret) {
            __leave2;
        }
        pkey.release();  // cryptokey own pkey
    }
    __finally2 {
        if (eck) {
            EC_KEY_free(eck);
        }
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
