/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/crypto/crypto_hash.hpp>

namespace hotplace {
namespace crypto {

transcript_hash::transcript_hash(hash_algorithm_t alg) : _handle(nullptr) {
    _shared.make_share(this);

    openssl_hash hash;
    hash.open(&_handle, alg);
    hash.init(_handle);
}

transcript_hash::transcript_hash(const transcript_hash& rhs) {
    _shared.make_share(this);

    openssl_hash hash;
    hash.dup(&_handle, rhs._handle);
}

transcript_hash::~transcript_hash() {
    openssl_hash hash;
    hash.close(_handle);
}

transcript_hash* transcript_hash::dup() { return new transcript_hash(*this); }

void transcript_hash::reset() {
    openssl_hash hash;
    hash.init(_handle);
}

return_t transcript_hash::update(const binary_t& message) { return update(&message[0], message.size()); }

return_t transcript_hash::update(const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    openssl_hash hash;
    ret = hash.update(_handle, stream, size);
    return ret;
}

return_t transcript_hash::digest(const binary_t& message, binary_t& result) { return digest(&message[0], message.size(), result); }

return_t transcript_hash::digest(const byte_t* stream, size_t size, binary_t& result) {
    return_t ret = errorcode_t::success;
    openssl_hash hash;
    ret = hash.update(_handle, stream, size, result);
    return ret;
}

return_t transcript_hash::digest(binary_t& result) {
    return_t ret = errorcode_t::success;
    openssl_hash hash;
    ret = hash.update(_handle, nullptr, 0, result);
    return ret;
}

void transcript_hash::addref() { _shared.addref(); }

void transcript_hash::release() { _shared.delref(); }

transcript_hash_builder::transcript_hash_builder() : _alg(hash_alg_unknown) {}

transcript_hash* transcript_hash_builder::build() {
    transcript_hash* obj = nullptr;
    __try_new_catch_only(obj, new transcript_hash(_alg));
    return obj;
}

transcript_hash_builder& transcript_hash_builder::set(hash_algorithm_t alg) {
    _alg = alg;
    return *this;
}

}  // namespace crypto
}  // namespace hotplace
