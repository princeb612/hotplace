/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keychain_mldsa.cpp
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

        EVP_PKEY* pk = nullptr;
        ret = pkey_keygen_byname(nullptr, &pk, sn);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        EVP_PKEY_ptr pkey(pk);

        crypto_key_object key(pkey.get(), desc);
        ret = cryptokey->add(key);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        pkey.release();  // cryptokey own pkey
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keychain::add_mldsa_pub(crypto_key* cryptokey, uint32 nid, const binary_t& pub, key_encoding_t encoding, const keydesc& desc) {
    return add_mldsa_pub(cryptokey, nid, pub.data(), pub.size(), encoding, desc);
}

return_t crypto_keychain::add_mldsa_pub(crypto_key* cryptokey, uint32 nid, const byte_t* pub, size_t pubsize, key_encoding_t encoding, const keydesc& desc) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
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
        EVP_PKEY* pk = nullptr;
        switch (encoding) {
            case key_encoding_priv_pem:
            case key_encoding_encrypted_priv_pem:
            case key_encoding_pub_pem:
            case key_encoding_priv_der:
            case key_encoding_encrypted_priv_der:
            case key_encoding_pub_der: {
                ret = pkey_decode_format(nullptr, &pk, pub, pubsize, encoding);
            } break;
            case key_encoding_priv_raw:
            case key_encoding_pub_raw: {
                ret = pkey_decode_raw(nullptr, OBJ_nid2sn(nid), &pk, pub, pubsize, encoding);
            }
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }

        EVP_PKEY_ptr pkey(pk);

        uint32 id = 0;
        nidof_evp_pkey(pkey.get(), id);
        if (id != nid) {
            ret = errorcode_t::failed;
            __leave2;
        }

        crypto_key_object key(pkey.get(), desc);
        ret = cryptokey->add(key);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        pkey.release();  // cryptokey own pkey
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keychain::add_mldsa_priv(crypto_key* cryptokey, uint32 nid, const binary_t& keypair, key_encoding_t encoding, const keydesc& desc) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
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

        EVP_PKEY* pk = nullptr;
        ret = pkey_decode(nullptr, &pk, keypair, encoding);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        EVP_PKEY_ptr pkey(pk);

        uint32 id = 0;
        nidof_evp_pkey(pkey.get(), id);
        if (id != nid) {
            ret = errorcode_t::failed;
            __leave2;
        }

        crypto_key_object key(pkey.get(), desc);
        ret = cryptokey->add(key);
        if (success != ret) {
            __leave2;
        }
        pkey.release();  // cryptokey own pkey
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keychain::add_mldsa_pub_b64(crypto_key* cryptokey, uint32 nid, const char* pub, key_encoding_t encoding, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || (nullptr == pub)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64));
            }
        };

        binary_t bin_pub;

        os2b(pub, bin_pub);

        ret = add_mldsa_pub(cryptokey, nid, bin_pub, encoding, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_mldsa_pub_b64u(crypto_key* cryptokey, uint32 nid, const char* pub, key_encoding_t encoding, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || (nullptr == pub)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64url));
            }
        };

        binary_t bin_pub;

        os2b(pub, bin_pub);

        ret = add_mldsa_pub(cryptokey, nid, bin_pub, encoding, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_mldsa_pub_b16(crypto_key* cryptokey, uint32 nid, const char* pub, key_encoding_t encoding, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || (nullptr == pub)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode(input, strlen(input)));
            }
        };

        binary_t bin_pub;

        os2b(pub, bin_pub);

        ret = add_mldsa_pub(cryptokey, nid, bin_pub, encoding, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_mldsa_pub_b16rfc(crypto_key* cryptokey, uint32 nid, const char* pub, key_encoding_t encoding, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || (nullptr == pub)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode_rfc(std::string(input)));
            }
        };

        binary_t bin_pub;

        os2b(pub, bin_pub);

        ret = add_mldsa_pub(cryptokey, nid, bin_pub, encoding, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_mldsa_priv_b64(crypto_key* cryptokey, uint32 nid, const char* keypair, key_encoding_t encoding, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || (nullptr == keypair)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64));
            }
        };

        binary_t bin_keypair;

        os2b(keypair, bin_keypair);

        ret = add_mldsa_pub(cryptokey, nid, bin_keypair, encoding, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_mldsa_priv_b64u(crypto_key* cryptokey, uint32 nid, const char* keypair, key_encoding_t encoding, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || (nullptr == keypair)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64url));
            }
        };

        binary_t bin_keypair;

        os2b(keypair, bin_keypair);

        ret = add_mldsa_pub(cryptokey, nid, bin_keypair, encoding, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_mldsa_priv_b16(crypto_key* cryptokey, uint32 nid, const char* keypair, key_encoding_t encoding, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || (nullptr == keypair)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode(input, strlen(input)));
            }
        };

        binary_t bin_keypair;

        os2b(keypair, bin_keypair);

        ret = add_mldsa_pub(cryptokey, nid, bin_keypair, encoding, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_mldsa_priv_b16rfc(crypto_key* cryptokey, uint32 nid, const char* keypair, key_encoding_t encoding, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || (nullptr == keypair)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode_rfc(std::string(input)));
            }
        };

        binary_t bin_keypair;

        os2b(keypair, bin_keypair);

        ret = add_mldsa_pub(cryptokey, nid, bin_keypair, encoding, desc);
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
