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

crypto_hash::crypto_hash(hash_algorithm_t alg) : _alg(alg) { _shared.make_share(this); }

return_t crypto_hash::digest(const binary_t& message, binary_t& result) { return digest(&message[0], message.size(), result); }

return_t crypto_hash::digest(const byte_t* stream, size_t size, binary_t& result) {
    return_t ret = errorcode_t::success;
    openssl_hash hash;
    hash_context_t* handle = nullptr;
    ret = hash.open(&handle, _alg);
    if (errorcode_t::success == ret) {
        hash.init(handle);
        hash.update(handle, stream, size);
        hash.finalize(handle, result);
        hash.close(handle);
    }
    return ret;
}

void crypto_hash::addref() { _shared.addref(); }

void crypto_hash::release() { _shared.delref(); }

}  // namespace crypto
}  // namespace hotplace
