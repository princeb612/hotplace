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
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_keychain::add_mldsa(crypto_key* cryptokey, uint32 nid, const keydesc& desc) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    EVP_PKEY* pkey = nullptr;
    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        auto kty = ktyof_nid(nid);
        if (kty_mldsa != kty) {
            ret = errorcode_t::different_type;
            __leave2;
        }
        auto sn = OBJ_nid2sn(nid);
        if (nullptr == sn) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        ret = pkey_keygen_byname(nullptr, &pkey, sn);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        if (pkey) {
            crypto_key_object key(pkey, desc);
            ret = cryptokey->add(key);
        } else {
            ret = errorcode_t::internal_error;
            __leave2;
        }
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keychain::add_mldsa_pub(crypto_key* cryptokey, uint32 nid, const byte_t* pub, size_t pubsize, key_encoding_t encoding, const keydesc& desc) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    EVP_PKEY* pkey = nullptr;
    __try2 {
        if (nullptr == cryptokey || nullptr == pub) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        auto kty = ktyof_nid(nid);
        if (kty_mldsa != kty) {
            ret = errorcode_t::different_type;
            __leave2;
        }
        switch (encoding) {
            case key_encoding_priv_pem:
            case key_encoding_encrypted_priv_pem:
            case key_encoding_pub_pem:
            case key_encoding_priv_der:
            case key_encoding_encrypted_priv_der:
            case key_encoding_pub_der: {
                ret = pkey_decode_format(nullptr, &pkey, pub, pubsize, encoding);
            } break;
            case key_encoding_priv_raw:
            case key_encoding_pub_raw: {
                ret = pkey_decode_raw(nullptr, OBJ_nid2sn(nid), &pkey, pub, pubsize, encoding);
            }
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }
        uint32 id = 0;
        nidof_evp_pkey(pkey, id);
        if (id != nid) {
            ret = errorcode_t::failed;
            __leave2;
        }
        if (pkey) {
            crypto_key_object key(pkey, desc);
            ret = cryptokey->add(key);
        } else {
            ret = errorcode_t::internal_error;
            __leave2;
        }
    }
    __finally2 {
        if (success != ret) {
            if (pkey) {
                EVP_PKEY_free(pkey);
            }
        }
    }
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keychain::add_mldsa_priv(crypto_key* cryptokey, uint32 nid, const binary_t& keypair, key_encoding_t encoding, const keydesc& desc) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    EVP_PKEY* pkey = nullptr;
    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        auto kty = ktyof_nid(nid);
        if (kty_mldsa != kty) {
            ret = errorcode_t::different_type;
            __leave2;
        }
        ret = pkey_decode(nullptr, &pkey, keypair, encoding);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        uint32 id = 0;
        nidof_evp_pkey(pkey, id);
        if (id != nid) {
            ret = errorcode_t::failed;
            __leave2;
        }
        if (pkey) {
            crypto_key_object key(pkey, desc);
            ret = cryptokey->add(key);
        } else {
            ret = errorcode_t::internal_error;
            __leave2;
        }
    }
    __finally2 {
        if (success != ret) {
            if (pkey) {
                EVP_PKEY_free(pkey);
            }
        }
    }
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
