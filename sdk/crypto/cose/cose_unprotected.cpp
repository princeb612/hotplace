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

#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_sign.hpp>
#include <sdk/crypto/cose/cbor_object_signing.hpp>
#include <sdk/crypto/cose/cose_composer.hpp>
#include <sdk/crypto/crypto_advisor.hpp>

namespace hotplace {
namespace crypto {

cose_unprotected::cose_unprotected() {}

cose_unprotected::~cose_unprotected() {}

cose_unprotected& cose_unprotected::add(cose_key_t key, int32 value) {
    _unprotected.add(key, value);
    return *this;
}

cose_unprotected& cose_unprotected::add(cose_key_t key, const char* value) {
    _unprotected.add(key, value);
    return *this;
}

cose_unprotected& cose_unprotected::add(cose_key_t key, std::string& value) {
    _unprotected.add(key, value);
    return *this;
}

cose_unprotected& cose_unprotected::add(cose_key_t key, const std::string& value) {
    _unprotected.add(key, value);
    return *this;
}

cose_unprotected& cose_unprotected::add(cose_key_t key, binary_t& value) {
    _unprotected.add(key, value);
    return *this;
}

cose_unprotected& cose_unprotected::add(cose_key_t key, const binary_t& value) {
    _unprotected.add(key, value);
    return *this;
}

cose_unprotected& cose_unprotected::add(cose_key_t key, uint16 curve, const binary_t& x, const binary_t& y) {
    _unprotected.add(key, curve, x, y);
    return *this;
}

cose_unprotected& cose_unprotected::add(cose_key_t key, uint16 curve, const binary_t& x, bool ysign) {
    _unprotected.add(key, curve, x, ysign);
    return *this;
}

cose_unprotected& cose_unprotected::add(cose_alg_t alg, const char* kid, const binary_t& signature) {
    _unprotected.add(alg, kid, signature);
    return *this;
}

return_t cose_unprotected::set(cbor_map* object) { return _unprotected.parse_unprotected(object); }

cose_data& cose_unprotected::data() { return _unprotected; }

cose_unprotected& cose_unprotected::clear() {
    _unprotected.clear();
    return *this;
}

cbor_map* cose_unprotected::cbor() {
    cbor_map* object = nullptr;
    _unprotected.build_unprotected(&object);
    return object;
}

}  // namespace crypto
}  // namespace hotplace
