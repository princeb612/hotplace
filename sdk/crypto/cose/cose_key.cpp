/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 8152 CBOR Object Signing and Encryption (COSE)
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/openssl_crypt.hpp>
#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sign.hpp>
#include <hotplace/sdk/crypto/cose/cbor_object_signing.hpp>
#include <hotplace/sdk/crypto/cose/cose_composer.hpp>

namespace hotplace {
namespace crypto {

cose_data::cose_key::cose_key() : _curve(0) {}

void cose_data::cose_key::set(crypto_key* key, uint16 curve, const binary_t& x, const binary_t& y) {
    _curve = curve;
    _x = x;
    _y = y;
    _compressed = false;

    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_curve_t* hint = advisor->hintof_curve((cose_ec_curve_t)curve);
    crypto_keychain keychain;
    binary_t d;
    keychain.add_ec(key, hint->nid, x, y, d, keydesc());
}

void cose_data::cose_key::set(crypto_key* key, uint16 curve, const binary_t& x, bool ysign) {
    _curve = curve;
    _x = x;
    _y.clear();
    _ysign = ysign;
    _compressed = true;

    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_curve_t* hint = advisor->hintof_curve((cose_ec_curve_t)curve);
    crypto_keychain keychain;
    binary_t d;
    keychain.add_ec_compressed(key, hint->nid, x, ysign, d, keydesc());
}

void cose_data::cose_key::set(cose_orderlist_t& order) { _order = order; }

cbor_map* cose_data::cose_key::cbor() {
    cbor_map* object = nullptr;
    __try2 {
        __try_new_catch_only(object, new cbor_map());
        if (nullptr == object) {
            __leave2;
        }

        cose_kty_t kty;
        switch (_curve) {
            case cose_ec_p256:
            case cose_ec_p384:
            case cose_ec_p521:
                kty = cose_kty_t::cose_kty_ec2;
                break;
            default:
                kty = cose_kty_t::cose_kty_okp;
                break;
        }

        if (_order.size()) {
            for (const auto& key : _order) {
                switch (key) {
                    case cose_key_lable_t::cose_lable_kty:
                        *object << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(kty));
                        break;
                    case cose_key_lable_t::cose_ec_crv:
                        *object << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(_curve));
                        break;
                    case cose_key_lable_t::cose_ec_x:
                        *object << new cbor_pair(cose_key_lable_t::cose_ec_x, new cbor_data(_x));
                        break;
                    case cose_key_lable_t::cose_ec_y:
                        if (_compressed) {
                            *object << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(_ysign));  // y(-3)
                        } else {
                            *object << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(_y));  // y(-3)
                        }
                        break;
                    default:
                        break;
                }
            }
        } else {
            *object << new cbor_pair(cose_key_lable_t::cose_lable_kty, new cbor_data(kty))  // kty(1)
                    << new cbor_pair(cose_key_lable_t::cose_ec_crv, new cbor_data(_curve))  // crv(-1)
                    << new cbor_pair(cose_key_lable_t::cose_ec_x, new cbor_data(_x));       // x(-2)

            if (cose_kty_t::cose_kty_ec2 == kty) {
                if (_compressed) {
                    *object << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(_ysign));  // y(-3)
                } else {
                    *object << new cbor_pair(cose_key_lable_t::cose_ec_y, new cbor_data(_y));  // y(-3)
                }
            }
        }
    }
    __finally2 {}
    return object;
}

}  // namespace crypto
}  // namespace hotplace
