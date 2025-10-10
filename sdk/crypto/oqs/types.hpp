/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_OQS_TYPES__
#define __HOTPLACE_SDK_CRYPTO_OQS_TYPES__

#include <hotplace/sdk/base/system/types.hpp>
#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <set>

namespace hotplace {
namespace crypto {

struct oqs_context {
    OSSL_LIB_CTX* libctx;
    OSSL_PROVIDER* default_provider;
    OSSL_PROVIDER* oqs_provider;
    std::map<std::string, int> algs;
    std::list<std::pair<std::string, int>> kemalgs;
    std::list<std::pair<std::string, int>> sigalgs;

    oqs_context() : libctx(nullptr), default_provider(nullptr), oqs_provider(nullptr) {}
};

class pqc_oqs;

}  // namespace crypto
}  // namespace hotplace

#endif
