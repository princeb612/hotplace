/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keychain_ossl3.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keygen.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_keychain::pkey_keygen_byname(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const char* name) { return crypto_keygen::pkey_keygen_byname(libctx, pkey, name); }

return_t crypto_keychain::pkey_encode_format(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, binary_t& keydata, key_encoding_t encoding, const char* passphrase) {
    return crypto_keygen::pkey_encode_format(libctx, pkey, keydata, encoding, passphrase);
}

return_t crypto_keychain::pkey_decode_format(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const binary_t& keydata, key_encoding_t encoding, const char* passphrase) {
    return crypto_keygen::pkey_decode_format(libctx, pkey, keydata, encoding, passphrase);
}

return_t crypto_keychain::pkey_decode_format(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const byte_t* keystream, size_t keysize, key_encoding_t encoding,
                                             const char* passphrase) {
    return crypto_keygen::pkey_decode_format(libctx, pkey, keystream, keysize, encoding, passphrase);
}

return_t crypto_keychain::pkey_encode_raw(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, binary_t& keydata, key_encoding_t encoding) {
    return crypto_keygen::pkey_encode_raw(libctx, pkey, keydata, encoding);
}

return_t crypto_keychain::pkey_decode(OSSL_LIB_CTX* libctx, const char* name, EVP_PKEY** pkey, const binary_t& keydata, key_encoding_t encoding, const char* passphrase) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    __try2 {
        if (nullptr == pkey || keydata.empty()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = pkey_decode(libctx, name, pkey, keydata.data(), keydata.size(), encoding, passphrase);
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keychain::pkey_decode(OSSL_LIB_CTX* libctx, const char* name, EVP_PKEY** pkey, const byte_t* keystream, size_t keysize, key_encoding_t encoding,
                                      const char* passphrase) {
    return crypto_keygen::pkey_decode(libctx, name, pkey, keystream, keysize, encoding, passphrase);
}

return_t crypto_keychain::pkey_decode_raw(OSSL_LIB_CTX* libctx, const char* name, EVP_PKEY** pkey, const binary_t& keydata, key_encoding_t encoding) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    __try2 {
        if (nullptr == pkey || keydata.empty()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = pkey_decode_raw(libctx, name, pkey, keydata.data(), keydata.size(), encoding);
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keychain::pkey_decode_raw(OSSL_LIB_CTX* libctx, const char* name, EVP_PKEY** pkey, const byte_t* keystream, size_t keysize, key_encoding_t encoding) {
    return crypto_keygen::pkey_decode_raw(libctx, name, pkey, keystream, keysize, encoding);
}

return_t crypto_keychain::pkey_encode(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, binary_t& keydata, key_encoding_t encoding, const char* passphrase) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    switch (encoding) {
        case key_encoding_priv_pem:
        case key_encoding_encrypted_priv_pem:
        case key_encoding_pub_pem:
        case key_encoding_priv_der:
        case key_encoding_encrypted_priv_der:
        case key_encoding_pub_der: {
            ret = pkey_encode_format(libctx, pkey, keydata, encoding, passphrase);
        } break;
        case key_encoding_priv_raw:
        case key_encoding_pub_raw: {
            ret = pkey_encode_raw(libctx, pkey, keydata, encoding);
        } break;
    }
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keychain::pkey_decode(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const binary_t& keydata, key_encoding_t encoding, const char* passphrase) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    __try2 {
        if (nullptr == pkey || keydata.empty()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = pkey_decode(libctx, pkey, keydata.data(), keydata.size(), encoding, passphrase);
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keychain::pkey_decode(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const byte_t* keystream, size_t keysize, key_encoding_t encoding, const char* passphrase) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    switch (encoding) {
        case key_encoding_priv_pem:
        case key_encoding_encrypted_priv_pem:
        case key_encoding_pub_pem:
        case key_encoding_priv_der:
        case key_encoding_encrypted_priv_der:
        case key_encoding_pub_der: {
            ret = pkey_decode_format(libctx, pkey, keystream, keysize, encoding, passphrase);
        } break;
        case key_encoding_priv_raw:
        case key_encoding_pub_raw: {
            ret = errorcode_t::not_supported;
        } break;
    }
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

bool crypto_keychain::pkey_is_private(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey) { return crypto_keygen::pkey_is_private(libctx, pkey); }

return_t crypto_keychain::add_ossl3(crypto_key* cryptokey, uint32 nid, keydesc&& desc) { return crypto_keygen::add_ossl3(cryptokey, nid, std::forward<keydesc>(desc)); }

return_t crypto_keychain::add_ossl3(crypto_key* cryptokey, const char* name, keydesc&& desc) {
    return crypto_keygen::add_ossl3(cryptokey, name, std::forward<keydesc>(desc));
}

return_t crypto_keychain::add_ossl3(crypto_key* cryptokey, uint32 nid, const binary_t& keydata, key_encoding_t encoding, keydesc&& desc) {
    return add_ossl3(cryptokey, nid, keydata.data(), keydata.size(), encoding, std::forward<keydesc>(desc));
}

return_t crypto_keychain::add_ossl3(crypto_key* cryptokey, uint32 nid, const byte_t* keydata, size_t keysize, key_encoding_t encoding, keydesc&& desc) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    __try2 {
        if (nullptr == cryptokey || nullptr == keydata) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const char* name = OBJ_nid2ln(nid);
        if (nullptr == name) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = add_ossl3(cryptokey, name, keydata, keysize, encoding, std::forward<keydesc>(desc));
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keychain::add_ossl3(crypto_key* cryptokey, const char* name, const binary_t& keydata, key_encoding_t encoding, keydesc&& desc) {
    return crypto_keygen::add_ossl3(cryptokey, name, keydata.data(), keydata.size(), encoding, std::forward<keydesc>(desc));
}

return_t crypto_keychain::add_ossl3(crypto_key* cryptokey, const char* name, const byte_t* keydata, size_t keysize, key_encoding_t encoding, keydesc&& desc) {
    return crypto_keygen::add_ossl3(cryptokey, name, keydata, keysize, encoding, std::forward<keydesc>(desc));
}

return_t crypto_keychain::add_ossl3(crypto_key* cryptokey, uint32 nid, encoding_t fmt, const char* key, key_encoding_t encoding, keydesc&& desc) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    __try2 {
        if (nullptr == cryptokey || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        switch (fmt) {
            case encoding_t::encoding_base64: {
                ret = add_ossl3_b64(cryptokey, nid, key, encoding, std::forward<keydesc>(desc));
            } break;
            case encoding_t::encoding_base64url: {
                ret = add_ossl3_b64u(cryptokey, nid, key, encoding, std::forward<keydesc>(desc));
            } break;
            case encoding_t::encoding_base16: {
                ret = add_ossl3_b16(cryptokey, nid, key, encoding, std::forward<keydesc>(desc));
            } break;
            case encoding_t::encoding_base16rfc: {
                ret = add_ossl3_b16rfc(cryptokey, nid, key, encoding, std::forward<keydesc>(desc));
            } break;
            default: {
                ret = errorcode_t::bad_request;
            } break;
        }
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keychain::add_ossl3(crypto_key* cryptokey, const char* name, encoding_t fmt, const char* key, key_encoding_t encoding, keydesc&& desc) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    __try2 {
        if (nullptr == cryptokey || nullptr == name || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        switch (fmt) {
            case encoding_t::encoding_base64: {
                ret = add_ossl3_b64(cryptokey, name, key, encoding, std::forward<keydesc>(desc));
            } break;
            case encoding_t::encoding_base64url: {
                ret = add_ossl3_b64u(cryptokey, name, key, encoding, std::forward<keydesc>(desc));
            } break;
            case encoding_t::encoding_base16: {
                ret = add_ossl3_b16(cryptokey, name, key, encoding, std::forward<keydesc>(desc));
            } break;
            case encoding_t::encoding_base16rfc: {
                ret = add_ossl3_b16rfc(cryptokey, name, key, encoding, std::forward<keydesc>(desc));
            } break;
            default: {
                ret = errorcode_t::bad_request;
            } break;
        }
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keychain::add_ossl3_b64(crypto_key* cryptokey, uint32 nid, const char* key, key_encoding_t encoding, keydesc&& desc) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    __try2 {
        if (nullptr == cryptokey || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64));
            }
        };

        binary_t bin;

        os2b(key, bin);

        ret = add_ossl3(cryptokey, nid, bin, encoding, std::forward<keydesc>(desc));
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keychain::add_ossl3_b64u(crypto_key* cryptokey, uint32 nid, const char* key, key_encoding_t encoding, keydesc&& desc) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    __try2 {
        if (nullptr == cryptokey || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64url));
            }
        };

        binary_t bin;

        os2b(key, bin);

        ret = add_ossl3(cryptokey, nid, bin, encoding, std::forward<keydesc>(desc));
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keychain::add_ossl3_b16(crypto_key* cryptokey, uint32 nid, const char* key, key_encoding_t encoding, keydesc&& desc) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    __try2 {
        if (nullptr == cryptokey || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode(input, strlen(input)));
            }
        };

        binary_t bin;

        os2b(key, bin);

        ret = add_ossl3(cryptokey, nid, bin, encoding, std::forward<keydesc>(desc));
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keychain::add_ossl3_b16rfc(crypto_key* cryptokey, uint32 nid, const char* key, key_encoding_t encoding, keydesc&& desc) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    __try2 {
        if (nullptr == cryptokey || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode_rfc(std::string(input)));
            }
        };

        binary_t bin;

        os2b(key, bin);

        ret = add_ossl3(cryptokey, nid, bin, encoding, std::forward<keydesc>(desc));
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keychain::add_ossl3_b64(crypto_key* cryptokey, const char* name, const char* key, key_encoding_t encoding, keydesc&& desc) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    __try2 {
        if (nullptr == cryptokey || nullptr == name || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64));
            }
        };

        binary_t bin;

        os2b(key, bin);

        ret = add_ossl3(cryptokey, name, bin, encoding, std::forward<keydesc>(desc));
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keychain::add_ossl3_b64u(crypto_key* cryptokey, const char* name, const char* key, key_encoding_t encoding, keydesc&& desc) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    __try2 {
        if (nullptr == cryptokey || nullptr == name || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64url));
            }
        };

        binary_t bin;

        os2b(key, bin);

        ret = add_ossl3(cryptokey, name, bin, encoding, std::forward<keydesc>(desc));
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keychain::add_ossl3_b16(crypto_key* cryptokey, const char* name, const char* key, key_encoding_t encoding, keydesc&& desc) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    __try2 {
        if (nullptr == cryptokey || nullptr == name || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode(input, strlen(input)));
            }
        };

        binary_t bin;

        os2b(key, bin);

        ret = add_ossl3(cryptokey, name, bin, encoding, std::forward<keydesc>(desc));
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keychain::add_ossl3_b16rfc(crypto_key* cryptokey, const char* name, const char* key, key_encoding_t encoding, keydesc&& desc) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    __try2 {
        if (nullptr == cryptokey || nullptr == name || nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode_rfc(std::string(input)));
            }
        };

        binary_t bin;

        os2b(key, bin);

        ret = add_ossl3(cryptokey, name, bin, encoding, std::forward<keydesc>(desc));
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
