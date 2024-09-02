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

#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_sign.hpp>
#include <sdk/crypto/cose/cbor_object_signing.hpp>
#include <sdk/crypto/cose/cose_composer.hpp>

namespace hotplace {
using namespace io;
namespace crypto {

cose_unsent::cose_unsent() {}

cose_unsent::~cose_unsent() {}

cose_data& cose_unsent::data() { return _unsent; }

bool cose_unsent::isvalid(int key) {
    bool ret = true;
    switch (key) {
        case cose_param_t::cose_external:
        case cose_param_t::cose_unsent_apu_id:
        case cose_param_t::cose_unsent_apu_nonce:
        case cose_param_t::cose_unsent_apu_other:
        case cose_param_t::cose_unsent_apv_id:
        case cose_param_t::cose_unsent_apv_nonce:
        case cose_param_t::cose_unsent_apv_other:
        case cose_param_t::cose_unsent_pub_other:
        case cose_param_t::cose_unsent_priv_other:
        case cose_param_t::cose_unsent_iv:
        case cose_param_t::cose_unsent_alg:
        case cose_param_t::cose_param_cek:
            break;
        default:
            ret = false;
            break;
    }
    return ret;
}

cose_unsent& cose_unsent::add(int key, const char* value) {
    if (value && isvalid(key)) {
        _unsent.add(key, value);
    }
    return *this;
}

cose_unsent& cose_unsent::add(int key, const unsigned char* value, size_t size) {
    if (value && isvalid(key)) {
        _unsent.add(key, value, size);
    }
    return *this;
}

cose_unsent& cose_unsent::add(int key, binary_t& value) {
    if (isvalid(key)) {
        _unsent.add(key, value);
    }
    return *this;
}

cose_unsent& cose_unsent::add(int key, const binary_t& value) {
    if (isvalid(key)) {
        _unsent.add(key, value);
    }
    return *this;
}

}  // namespace crypto
}  // namespace hotplace
