/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keychain_ec.cpp
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

return_t crypto_keychain::add_ec(crypto_key* cryptokey, uint32 nid, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    int rc = 0;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        int type = EVP_PKEY_EC;  // EVP_PKEY_CTX_new_id type

        auto hint = advisor->hintof_curve_nid(nid);
        if (nullptr == hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        auto kty = ktyof(hint);
        if (kty_ec != kty) {
            ret = errorcode_t::different_type;
            __leave2;
        }

        EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(type, nullptr));
        if (nullptr == ctx.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        rc = EVP_PKEY_keygen_init(ctx.get());
        if (rc < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
        rc = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), nid);
        if (rc < 1) {
            ret = errorcode_t::not_supported;
            __leave2_trace_openssl(ret);
        }

        EVP_PKEY* pk = nullptr;
        rc = EVP_PKEY_keygen(ctx.get(), &pk);
        if (rc < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
        if (nullptr == pk) { /* [openssl 3.0.3] return success but pkey is nullptr */
            ret = errorcode_t::internal_error;
            __leave2;
        }

        EVP_PKEY_ptr pkey(pk);

        // set ASN.1 OPENSSL_EC_NAMED_CURVE flag for PEM export (PEM_write_bio_PUBKEY, PEM_write_bio_PrivateKey)
        EC_KEY_set_asn1_flag((EC_KEY*)EVP_PKEY_get0_EC_KEY(pkey.get()), OPENSSL_EC_NAMED_CURVE);  // openssl 3.0 EVP_PKEY_get0 family return const key pointer

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

return_t crypto_keychain::add_ec(crypto_key* cryptokey, uint32 nid, const binary_t& x, const binary_t& y, const binary_t& d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    int rc = 1;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_advisor* advisor = crypto_advisor::get_instance();
        auto hint = advisor->hintof_curve_nid(nid);
        if (nullptr == hint) {
            ret = errorcode_t::bad_request;
            __leave2;
        }
        auto kty = ktyof(hint);
        if (kty_ec != kty) {
            ret = errorcode_t::different_type;
            __leave2;
        }

        BN_ptr bn_x(BN_bin2bn(x.data(), x.size(), nullptr));
        BN_ptr bn_y(BN_bin2bn(y.data(), y.size(), nullptr));
        BN_ptr bn_d;
        if (d.size() > 0) {
            bn_d = std::move(BN_ptr(BN_bin2bn(d.data(), d.size(), nullptr)));
        }

        if (nullptr == bn_x.get() && nullptr == bn_y.get()) {
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

        if (nullptr != bn_d) {
            rc = EC_KEY_set_private_key(ec.get(), bn_d.get());
            if (rc != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }

            rc = EC_POINT_mul(group, point.get(), bn_d.get(), nullptr, nullptr, nullptr);
            if (rc != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        } else {
            rc = EC_POINT_set_affine_coordinates(group, point.get(), bn_x.get(), bn_y.get(), nullptr);  // EC_POINT_set_affine_coordinates_GFp
            if (rc != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        }

        rc = EC_KEY_set_public_key(ec.get(), point.get());
        if (rc != 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        EVP_PKEY_ptr pkey(EVP_PKEY_new());
        EVP_PKEY_set1_EC_KEY(pkey.get(), ec.get());  // EC_KEY_up_ref
        if (rc != 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

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

return_t crypto_keychain::add_ec(crypto_key* cryptokey, uint32 nid, jwa_t alg, const binary_t& x, const binary_t& y, const binary_t& d, const keydesc& desc) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm(alg);
    keydesc kd(desc);
    if (hint) {
        kd.set_alg(nameof_alg(hint));
    }
    return add_ec(cryptokey, nid, x, y, d, std::move(kd));
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

        ret = add_ec2(cryptokey, nid, desc);
    }
    __finally2 {}
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

        ret = add_ec2(cryptokey, nid, x, y, d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_b64(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || (nullptr == x && nullptr == d)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64));
            }
        };

        binary_t bin_x;
        binary_t bin_y;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(y, bin_y);
        os2b(d, bin_d);

        ret = add_ec2(cryptokey, nid, bin_x, bin_y, bin_d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_b64u(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || (nullptr == x && nullptr == d)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64url));
            }
        };

        binary_t bin_x;
        binary_t bin_y;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(y, bin_y);
        os2b(d, bin_d);

        ret = add_ec2(cryptokey, nid, bin_x, bin_y, bin_d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_b16(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || (nullptr == x && nullptr == d)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode(input, strlen(input)));
            }
        };

        binary_t bin_x;
        binary_t bin_y;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(y, bin_y);
        os2b(d, bin_d);

        ret = add_ec2(cryptokey, nid, bin_x, bin_y, bin_d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_b16rfc(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || (nullptr == x && nullptr == d)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode_rfc(std::string(input)));
            }
        };

        binary_t bin_x;
        binary_t bin_y;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(y, bin_y);
        os2b(d, bin_d);

        ret = add_ec2(cryptokey, nid, bin_x, bin_y, bin_d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_b64(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || (nullptr == x && nullptr == d)) {
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
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_b64u(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || (nullptr == x && nullptr == d)) {
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
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_b16(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || (nullptr == x && nullptr == d)) {
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
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_b16rfc(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || (nullptr == x && nullptr == d)) {
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
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
