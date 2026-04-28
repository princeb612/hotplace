/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keychain_ec_compressed.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_keychain::add_ec_compressed(crypto_key* cryptokey, uint32 nid, const binary_t& x, bool ysign, const binary_t& d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    int ret_openssl = 1;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        BN_ptr bn_x(BN_bin2bn(x.data(), x.size(), nullptr));
        BN_ptr bn_d;
        if (d.size() > 0) {
            bn_d = std::move(BN_ptr(BN_bin2bn(d.data(), d.size(), nullptr)));
        }

        if (nullptr == bn_x.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        EC_KEY_ptr ec(EC_KEY_new_by_curve_name(nid));
        if (nullptr == ec.get()) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        const EC_GROUP* group = EC_KEY_get0_group(ec.get());
        EC_POINT_ptr point(EC_POINT_new(group));
        if (nullptr == point.get()) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        if (nullptr != bn_d.get()) {
            ret_openssl = EC_KEY_set_private_key(ec.get(), bn_d.get());
            if (ret_openssl != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
            bn_d.release();  // ec own bn_d

            ret_openssl = EC_POINT_mul(group, point.get(), bn_d.get(), nullptr, nullptr, nullptr);
            if (ret_openssl != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        } else {
            ret_openssl = EC_POINT_set_compressed_coordinates(group, point.get(), bn_x.get(), ysign, nullptr);  // EC_POINT_set_compressed_coordinates_GFp
            if (ret_openssl != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        }

        ret_openssl = EC_KEY_set_public_key(ec.get(), point.get());
        if (ret_openssl != 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        EVP_PKEY_ptr pkey(EVP_PKEY_new());
        EVP_PKEY_set1_EC_KEY(pkey.get(), ec.get());
        if (ret_openssl != 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
        // ec using set1_family (internally upref)

        crypto_key_object key(pkey.get(), desc);
        ret = cryptokey->add(key);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        pkey.release();  // cryptokey own pkey
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_compressed(crypto_key* cryptokey, uint32 nid, encoding_t encoding, const char* x, bool ysign, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    switch (encoding) {
        case encoding_t::encoding_base64:
            ret = add_ec_compressed_b64(cryptokey, nid, x, ysign, d, desc);
            break;
        case encoding_t::encoding_base64url:
            ret = add_ec_compressed_b64u(cryptokey, nid, x, ysign, d, desc);
            break;
        case encoding_t::encoding_base16:
            ret = add_ec_compressed_b16(cryptokey, nid, x, ysign, d, desc);
            break;
        case encoding_t::encoding_base16rfc:
            ret = add_ec_compressed_b16rfc(cryptokey, nid, x, ysign, d, desc);
            break;
    }
    return ret;
}

return_t crypto_keychain::add_ec_compressed_b64(crypto_key* cryptokey, uint32 nid, const char* x, bool ysign, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64));
            }
        };

        binary_t bin_x;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(d, bin_d);

        ret = add_ec_compressed(cryptokey, nid, bin_x, ysign, bin_d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_compressed_b64u(crypto_key* cryptokey, uint32 nid, const char* x, bool ysign, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64url));
            }
        };

        binary_t bin_x;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(d, bin_d);

        ret = add_ec_compressed(cryptokey, nid, bin_x, ysign, bin_d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_compressed_b16(crypto_key* cryptokey, uint32 nid, const char* x, bool ysign, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode(input, strlen(input)));
            }
        };

        binary_t bin_x;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(d, bin_d);

        ret = add_ec_compressed(cryptokey, nid, bin_x, ysign, bin_d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_compressed_b16rfc(crypto_key* cryptokey, uint32 nid, const char* x, bool ysign, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode_rfc(std::string(input)));
            }
        };

        binary_t bin_x;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(d, bin_d);

        ret = add_ec_compressed(cryptokey, nid, bin_x, ysign, bin_d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_compressed(crypto_key* cryptokey, const char* curve, encoding_t encoding, const char* x, bool ysign, const char* d,
                                            const keydesc& desc) {
    return_t ret = errorcode_t::success;
    switch (encoding) {
        case encoding_t::encoding_base64:
            ret = add_ec_compressed_b64(cryptokey, curve, x, ysign, d, desc);
            break;
        case encoding_t::encoding_base64url:
            ret = add_ec_compressed_b64u(cryptokey, curve, x, ysign, d, desc);
            break;
        case encoding_t::encoding_base16:
            ret = add_ec_compressed_b16(cryptokey, curve, x, ysign, d, desc);
            break;
        case encoding_t::encoding_base16rfc:
            ret = add_ec_compressed_b16rfc(cryptokey, curve, x, ysign, d, desc);
            break;
    }
    return ret;
}

return_t crypto_keychain::add_ec_compressed_b64(crypto_key* cryptokey, const char* curve, const char* x, bool ysign, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec_compressed_b64(cryptokey, nid, x, ysign, d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_compressed_b64u(crypto_key* cryptokey, const char* curve, const char* x, bool ysign, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec_compressed_b64u(cryptokey, nid, x, ysign, d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_compressed_b16(crypto_key* cryptokey, const char* curve, const char* x, bool ysign, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec_compressed_b16(cryptokey, nid, x, ysign, d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_compressed_b16rfc(crypto_key* cryptokey, const char* curve, const char* x, bool ysign, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec_compressed_b16rfc(cryptokey, nid, x, ysign, d, desc);
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
