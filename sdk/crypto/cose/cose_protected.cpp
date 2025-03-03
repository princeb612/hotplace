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
namespace crypto {

cose_protected::cose_protected() {}

cose_protected::~cose_protected() {}

cose_protected& cose_protected::add(cose_key_t key, uint32 value) {
    _protected.add(key, value);
    return *this;
}

cose_protected& cose_protected::set(const binary_t& bin) {
    _protected.set(bin);
    cbor_object* root = nullptr;
    cbor_parse(&root, bin);
    if (root) {
        cbor_data* object = cbor_typeof<cbor_data>(root, cbor_type_t::cbor_type_data);
        if (object) {
            set(object);
        }
        root->release();
    }
    return *this;
}

return_t cose_protected::set(cbor_data* object) { return _protected.parse_protected(object); }

cose_data& cose_protected::data() { return _protected; }

cose_protected& cose_protected::clear() {
    _protected.clear();
    return *this;
}

cbor_data* cose_protected::cbor() {
    cbor_data* object = nullptr;
    _protected.build_protected(&object);
    return object;
}

}  // namespace crypto
}  // namespace hotplace
