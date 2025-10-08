/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_PQC_TYPES__
#define __HOTPLACE_SDK_CRYPTO_PQC_TYPES__

#include <hotplace/sdk/base/system/types.hpp>
#include <set>

namespace hotplace {
namespace crypto {

#define OQS_KEY_ENCODING_PEM 0x00000001
#define OQS_KEY_ENCODING_DER 0x00000002
#define OQS_KEY_ENCODING_PRIV_ENCRYPTED 0xc0000000
#define OQS_KEY_ENCODING_PRIV 0x80000000
#define OQS_KEY_ENCODING_PUB 0x00000000

enum oqs_key_encoding_t : uint32 {
    oqs_key_encoding_priv_pem = OQS_KEY_ENCODING_PRIV | OQS_KEY_ENCODING_PEM,
    oqs_key_encoding_encrypted_priv_pem = OQS_KEY_ENCODING_PRIV_ENCRYPTED | OQS_KEY_ENCODING_PEM,
    oqs_key_encoding_pub_pem = OQS_KEY_ENCODING_PUB | OQS_KEY_ENCODING_PEM,
    oqs_key_encoding_priv_der = OQS_KEY_ENCODING_PRIV | OQS_KEY_ENCODING_DER,
    oqs_key_encoding_encrypted_priv_der = OQS_KEY_ENCODING_PRIV_ENCRYPTED | OQS_KEY_ENCODING_DER,
    oqs_key_encoding_pub_der = OQS_KEY_ENCODING_PUB | OQS_KEY_ENCODING_DER,
};

struct oqs_context {
    OSSL_LIB_CTX* libctx;
    OSSL_PROVIDER* default_provider;
    OSSL_PROVIDER* oqs_provider;
    std::map<std::string, int> algs;
    std::list<std::pair<std::string, int>> kemalgs;
    std::list<std::pair<std::string, int>> sigalgs;

    oqs_context() : libctx(nullptr), default_provider(nullptr), oqs_provider(nullptr) {}
};

class key_encapsulation;

}  // namespace crypto
}  // namespace hotplace

#endif
