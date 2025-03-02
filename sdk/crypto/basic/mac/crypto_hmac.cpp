/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_hmac.hpp>

namespace hotplace {
namespace crypto {

crypto_hmac::crypto_hmac(hash_algorithm_t alg, const binary_t& key) : _handle(nullptr), _alg(alg), _key(key) {
    openssl_hash hash;
    hash.open(&_handle, get_digest(), _key);
    hash.init(_handle);
    _shared.make_share(this);
}

crypto_hmac::~crypto_hmac() {
    if (_handle) {
        openssl_hash hash;
        hash.close(_handle);
    }
}

return_t crypto_hmac::mac(const binary_t& input, binary_t& output) { return mac(&input[0], input.size(), output); }

return_t crypto_hmac::mac(const byte_t* stream, size_t size, binary_t& output) {
    return_t ret = errorcode_t::success;
    openssl_hash hash;
    hash.init(_handle);
    hash.update(_handle, stream, size);
    hash.finalize(_handle, output);
    hash.init(_handle);
    return ret;
}

crypto_hmac& crypto_hmac::init() {
    openssl_hash hash;
    hash.init(_handle);
    return *this;
}

crypto_hmac& crypto_hmac::operator<<(const char* message) {
    if (message) {
        update((byte_t*)message, strlen(message));
    }
    return *this;
}

crypto_hmac& crypto_hmac::operator<<(const binary_t& message) { return update(message); }

crypto_hmac& crypto_hmac::update(const binary_t& message) {
    openssl_hash hash;
    hash.update(_handle, message);
    return *this;
}

crypto_hmac& crypto_hmac::update(const byte_t* stream, size_t size) {
    if (stream) {
        openssl_hash hash;
        hash.update(_handle, stream, size);
    }
    return *this;
}

template <typename T>
crypto_hmac& crypto_hmac::update(T value, std::function<T(T)> fn) {
    openssl_hash hash;
    if (fn) {
        T temp = fn(value);
        hash.update(_handle, (byte_t*)&temp, sizeof(T));
    } else {
        hash.update(_handle, (byte_t*)&value, sizeof(T));
    }
    return *this;
}

crypto_hmac& crypto_hmac::update(uint8 value, std::function<uint8(uint8)> fn) { return update<uint8>(value, fn); }

crypto_hmac& crypto_hmac::update(uint16 value, std::function<uint16(uint16)> fn) { return update<uint16>(value, fn); }

crypto_hmac& crypto_hmac::update(uint32 value, std::function<uint32(uint32)> fn) { return update<uint32>(value, fn); }

crypto_hmac& crypto_hmac::update(uint64 value, std::function<uint64(uint64)> fn) { return update<uint64>(value, fn); }

crypto_hmac& crypto_hmac::digest(binary_t& md) {
    openssl_hash hash;
    hash.update(_handle, nullptr, 0, md);
    return *this;
}

crypto_hmac& crypto_hmac::finalize(binary_t& md) {
    openssl_hash hash;
    hash.finalize(_handle, md);
    hash.init(_handle);
    return *this;
}

hash_algorithm_t crypto_hmac::get_digest() { return _alg; }

void crypto_hmac::addref() { _shared.addref(); }

void crypto_hmac::release() { _shared.delref(); }

}  // namespace crypto
}  // namespace hotplace
