/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_keychain::add_ec_compressed(crypto_key* cryptokey, uint32 nid, const binary_t& x, bool ysign, const binary_t& d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;
    EC_KEY* ec = nullptr;
    BIGNUM* bn_x = nullptr;
    BIGNUM* bn_d = nullptr;
    EC_POINT* pub = nullptr;
    EC_POINT* point = nullptr;
    BN_CTX* cfg = nullptr;
    int ret_openssl = 1;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        bn_x = BN_bin2bn(&x[0], x.size(), nullptr);
        if (d.size() > 0) {
            bn_d = BN_bin2bn(&d[0], d.size(), nullptr);
        }

        if (nullptr == bn_x) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        ec = EC_KEY_new_by_curve_name(nid);
        if (nullptr == ec) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        const EC_GROUP* group = EC_KEY_get0_group(ec);
        point = EC_POINT_new(group);
        if (nullptr == point) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        if (nullptr != bn_d) {
            ret_openssl = EC_KEY_set_private_key(ec, bn_d);
            if (ret_openssl != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }

            ret_openssl = EC_POINT_mul(group, point, bn_d, nullptr, nullptr, nullptr);
            if (ret_openssl != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        } else {
            /*
             * RFC8152 13.1.1.  Double Coordinate Curves
             * Compute the sign bit as laid out in the Elliptic-Curve-Point-to-Octet-String Conversion function of [SEC1]
             * If the sign bit is zero, then encode y as a CBOR false value; otherwise, encode y as a CBOR true value.
             */
            ret_openssl = EC_POINT_set_compressed_coordinates(group, point, bn_x, ysign, nullptr);  // EC_POINT_set_compressed_coordinates_GFp
            if (ret_openssl != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        }

        ret_openssl = EC_KEY_set_public_key(ec, point);
        if (ret_openssl != 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        pkey = EVP_PKEY_new();
        EVP_PKEY_set1_EC_KEY(pkey, ec);  // EC_KEY_up_ref
        if (ret_openssl != 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        crypto_key_object key(pkey, desc);
        ret = cryptokey->add(key);
    }
    __finally2 {
        if (ec) {
            EC_KEY_free(ec);
        }
        if (bn_x) {
            BN_clear_free(bn_x);
        }
        if (bn_d) {
            BN_clear_free(bn_d);
        }
        if (pub) {
            EC_POINT_free(pub);
        }
        if (point) {
            EC_POINT_free(point);
        }
        if (cfg) {
            BN_CTX_free(cfg);
        }

        if (errorcode_t::success != ret) {
            if (pkey) {
                EVP_PKEY_free(pkey);
            }
        }
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
    __finally2 {
        // do nothing
    }
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
    __finally2 {
        // do nothing
    }
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
    __finally2 {
        // do nothing
    }
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
    __finally2 {
        // do nothing
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
    __finally2 {
        // do nothing
    }
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
    __finally2 {
        // do nothing
    }
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
    __finally2 {
        // do nothing
    }
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
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
