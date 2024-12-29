/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <fstream>
#include <sdk/base/basic/binary.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>
#include <sdk/io/stream/file_stream.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_keychain::add_ec(crypto_key* cryptokey, uint32 nid, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = nullptr;
    int ret_openssl = 0;
    EVP_PKEY* params = nullptr;
    EVP_PKEY_CTX* keyctx = nullptr;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        int type = 0;  // EVP_PKEY_CTX_new_id type
        switch (nid) {
            case NID_X25519:
            case NID_ED25519:
            case NID_X448:
            case NID_ED448:
                type = nid;
                break;
            case NID_X9_62_prime256v1:
            case NID_secp256k1:
            case NID_secp384r1:
            case NID_secp521r1:
            // other curves ...
            default:
                type = EVP_PKEY_EC;
                break;
        }

        ctx = EVP_PKEY_CTX_new_id(type, nullptr);
        if (EVP_PKEY_EC == type) {
            ret_openssl = EVP_PKEY_paramgen_init(ctx);
            if (ret_openssl < 0) {
                ret = errorcode_t::internal_error;
                __leave2;
            }
            ret_openssl = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
            if (ret_openssl < 0) {
                ret = errorcode_t::not_supported;
                __leave2;
            }
            ret_openssl = EVP_PKEY_paramgen(ctx, &params);
            if (ret_openssl < 0) {
                ret = errorcode_t::internal_error;
                __leave2;
            }
            keyctx = EVP_PKEY_CTX_new(params, nullptr);
            if (nullptr == keyctx) {
                ret = errorcode_t::internal_error;
                __leave2;
            }
            ret_openssl = EVP_PKEY_keygen_init(keyctx);
            if (ret_openssl < 0) {
                ret = errorcode_t::internal_error;
                __leave2;
            }
            ret_openssl = EVP_PKEY_keygen(keyctx, &pkey);
            if (ret_openssl < 0) {
                ret = errorcode_t::internal_error;
                __leave2;
            }
            if (nullptr == pkey) { /* [openssl 3.0.3] return success but pkey is nullptr */
                ret = errorcode_t::internal_error;
                __leave2;
            }
            // set ASN.1 OPENSSL_EC_NAMED_CURVE flag for PEM export (PEM_write_bio_PUBKEY, PEM_write_bio_PrivateKey)
            EC_KEY_set_asn1_flag((EC_KEY*)EVP_PKEY_get0_EC_KEY(pkey), OPENSSL_EC_NAMED_CURVE);  // openssl 3.0 EVP_PKEY_get0 family return const key pointer
        } else {
            // OKP
            ret_openssl = EVP_PKEY_keygen_init(ctx);
            if (ret_openssl < 0) {
                ret = errorcode_t::internal_error;
                __leave2;
            }
            ret_openssl = EVP_PKEY_keygen(ctx, &pkey);
            if (ret_openssl < 0) {
                ret = errorcode_t::internal_error;
                __leave2;
            }
        }

        if (pkey) {
            crypto_key_object key(pkey, desc);
            ret = cryptokey->add(key);
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (pkey) {
                EVP_PKEY_free(pkey);
            }
        }
        if (keyctx) {
            EVP_PKEY_CTX_free(keyctx);
        }
        if (params) {
            EVP_PKEY_free(params);
        }

        if (ctx) {
            EVP_PKEY_CTX_free(ctx);
        }
    }
    return ret;
}

return_t crypto_keychain::add_ec(crypto_key* cryptokey, uint32 nid, const binary_t& x, const binary_t& y, const binary_t& d, const keydesc& desc) {
    return_t ret = errorcode_t::success;

    switch (nid) {
        case NID_X25519:
        case NID_X448:
        case NID_ED25519:
        case NID_ED448:
            ret = add_okp(cryptokey, nid, x, d, desc);
            break;
        case NID_X9_62_prime256v1:
        case NID_secp384r1:
        case NID_secp521r1:
        // other curves
        default:
            ret = add_ec2(cryptokey, nid, x, y, d, desc);
            break;
    }
    return ret;
}

return_t crypto_keychain::add_ec(crypto_key* cryptokey, uint32 nid, jwa_t alg, const binary_t& x, const binary_t& y, const binary_t& d, const keydesc& desc) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm(alg);
    keydesc kd(desc);
    if (hint) {
        kd.set_alg(nameof_alg(hint));
    }
    return add_ec(cryptokey, nid, x, y, d, desc);
}

return_t crypto_keychain::add_ec(crypto_key* cryptokey, const char* curve, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == cryptokey || nullptr == curve) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec(cryptokey, nid, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec(crypto_key* cryptokey, const char* curve, const binary_t& x, const binary_t& y, const binary_t& d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == cryptokey || nullptr == curve) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec(cryptokey, nid, x, y, d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec2(crypto_key* cryptokey, uint32 nid, const binary_t& x, const binary_t& y, const binary_t& d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;
    EC_KEY* ec = nullptr;
    BIGNUM* bn_x = nullptr;
    BIGNUM* bn_y = nullptr;
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
        bn_y = BN_bin2bn(&y[0], y.size(), nullptr);
        if (d.size() > 0) {
            bn_d = BN_bin2bn(&d[0], d.size(), nullptr);
        }

        if (nullptr == bn_x && nullptr == bn_y) {
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
            ret_openssl = EC_POINT_set_affine_coordinates(group, point, bn_x, bn_y, nullptr);  // EC_POINT_set_affine_coordinates_GFp
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
        if (bn_y) {
            BN_clear_free(bn_y);
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

return_t crypto_keychain::add_okp(crypto_key* cryptokey, uint32 nid, const binary_t& x, const binary_t& d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (d.size()) {
            pkey = EVP_PKEY_new_raw_private_key(nid, nullptr, &d[0], d.size());
        } else if (x.size()) {
            pkey = EVP_PKEY_new_raw_public_key(nid, nullptr, &x[0], x.size());
        }
        if (nullptr == pkey) {
            ret = errorcode_t::bad_request;
            __leave2_trace_openssl(ret);
        }

        crypto_key_object key(pkey, desc);
        cryptokey->add(key);
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (pkey) {
                EVP_PKEY_free(pkey);
            }
        }
    }
    return ret;
}

return_t crypto_keychain::add_ec_b64(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = base64_decode(input, strlen(input), base64_encoding_t::base64_encoding);
            }
        };

        binary_t bin_x;
        binary_t bin_y;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(y, bin_y);
        os2b(d, bin_d);

        ret = add_ec(cryptokey, nid, bin_x, bin_y, bin_d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b64u(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = base64_decode(input, strlen(input), base64_encoding_t::base64url_encoding);
            }
        };

        binary_t bin_x;
        binary_t bin_y;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(y, bin_y);
        os2b(d, bin_d);

        ret = add_ec(cryptokey, nid, bin_x, bin_y, bin_d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b16(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = base16_decode(input, strlen(input));
            }
        };

        binary_t bin_x;
        binary_t bin_y;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(y, bin_y);
        os2b(d, bin_d);

        ret = add_ec(cryptokey, nid, bin_x, bin_y, bin_d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b16rfc(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = base16_decode_rfc(std::string(input));
            }
        };

        binary_t bin_x;
        binary_t bin_y;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(y, bin_y);
        os2b(d, bin_d);

        ret = add_ec(cryptokey, nid, bin_x, bin_y, bin_d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b64(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc) {
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

        ret = add_ec_b64(cryptokey, nid, x, y, d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b64u(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc) {
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

        ret = add_ec_b64u(cryptokey, nid, x, y, d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b16(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc) {
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

        ret = add_ec_b16(cryptokey, nid, x, y, d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b16rfc(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc) {
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

        ret = add_ec_b16rfc(cryptokey, nid, x, y, d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
