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

cose_binary::cose_binary() {}

cose_binary& cose_binary::set_b16(const char* value) {
    _payload.set_b16(value);
    return *this;
}

cose_binary& cose_binary::set_b16(const std::string& value) {
    _payload.set_b16(value);
    return *this;
}

cose_binary& cose_binary::set(const std::string& value) {
    _payload.set(value);
    return *this;
}

cose_binary& cose_binary::set(const binary_t& value) {
    _payload.set(value);
    return *this;
}

return_t cose_binary::set(cbor_data* object) { return _payload.parse_payload(object); }

cose_data& cose_binary::data() { return _payload; }

bool cose_binary::empty() { return _payload.empty_binary(); }

size_t cose_binary::size() { return _payload.size_binary(); }

void cose_binary::get(binary_t& bin) { _payload.get_binary(bin); }

cose_binary& cose_binary::clear() {
    _payload.clear();
    return *this;
}

cbor_data* cose_binary::cbor() {
    cbor_data* object = nullptr;
    _payload.build_data(&object);
    return object;
}

}  // namespace crypto
}  // namespace hotplace
