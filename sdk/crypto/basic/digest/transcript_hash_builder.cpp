/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/transcript_hash.hpp>

namespace hotplace {
namespace crypto {

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
