/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_JOSE_TYPES__
#define __HOTPLACE_SDK_CRYPTO_JOSE_TYPES__

#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <hotplace/sdk/crypto/basic/types.hpp>
#include <hotplace/sdk/crypto/types.hpp>
#include <list>
#include <map>

namespace hotplace {
namespace crypto {

enum jose_compose_t {
    jose_enc_only = 1,
    jose_alg_only = 2,
    jose_enc_alg = 3,
};

enum jose_type_t {
    jose_alg_signature = 1,
    jose_alg_key_management = 2,
    jose_alg_contente_encryption = 3,
};

enum jose_part_t {
    jose_enc_part = 1,
    jose_alg_part = 2,
};

enum jose_flag_t {
    jose_deflate = (1 << 0),  // JWE only, (NOT JWS)
};

typedef struct _jose_recipient_t {
    const hint_jose_encryption_t* alg_info;
    EVP_PKEY* pkey;

    std::string header;
    std::string kid;

    crypt_datamap_t datamap;
    crypt_variantmap_t variantmap;  // p2c, epk
    const EVP_PKEY* epk;
    uint32 p2c;

    /* IV, TAG case of A128GCMKW, A192GCMKW, A256GCMKW */
    /* P2S, P2C case of PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW */
    /* EPK, APU, APV case of ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW */

    _jose_recipient_t() : alg_info(nullptr), pkey(nullptr), epk(nullptr), p2c(0) {}
} jose_recipient_t;
typedef std::map<jwa_t, jose_recipient_t> jose_recipients_t;
typedef std::pair<jose_recipients_t::iterator, bool> jose_recipients_pib_t;

/**
 * @brief encryption
 * @remarks
 *  flattened
 *      protected, iv, ciphertext, tag, encrypted_key
 *  json
 *      protected, iv, ciphertext, tag, recipients:[ header {alg:RSA1_5}, encrypted_key ]
 *      protected, iv, ciphertext, tag, recipients:[ header {alg:RSA-OAEP}, encrypted_key ]
 *      protected, iv, ciphertext, tag, recipients:[ header {alg:RSA-OAEP-256}, encrypted_key ]
 *      protected, iv, ciphertext, tag, recipients:[ header {alg:A128KW}, encrypted_key ]
 *      protected, iv, ciphertext, tag, recipients:[ header {alg:A192KW}, encrypted_key ]
 *      protected, iv, ciphertext, tag, recipients:[ header {alg:A256KW}, encrypted_key ]
 *      protected, iv, ciphertext, tag, recipients:[ header {alg:ECDH-ES+A128KW, epk}, encrypted_key ]
 *      protected, iv, ciphertext, tag, recipients:[ header {alg:ECDH-ES+A192KW, epk}, encrypted_key ]
 *      protected, iv, ciphertext, tag, recipients:[ header {alg:ECDH-ES+A256KW, epk}, encrypted_key ]
 *      protected, iv, ciphertext, tag, recipients:[ header {alg:A128GCMKW, iv, tag}, encrypted_key ]
 *      protected, iv, ciphertext, tag, recipients:[ header {alg:A192GCMKW, iv, tag}, encrypted_key ]
 *      protected, iv, ciphertext, tag, recipients:[ header {alg:A256GCMKW, iv, tag}, encrypted_key ]
 *      protected, iv, ciphertext, tag, recipients:[ header {alg:PBES2-HS256+A128KW, p2s, p2c}, encrypted_key ]
 *      protected, iv, ciphertext, tag, recipients:[ header {alg:PBES2-HS384+A192KW, p2s, p2c}, encrypted_key ]
 *      protected, iv, ciphertext, tag, recipients:[ header {alg:PBES2-HS512+A256KW, p2s, p2c}, encrypted_key ]
 */
typedef struct _jose_encryption_t {
    const hint_jose_encryption_t* enc_info;

    std::string header;
    std::string kid;
    crypt_datamap_t datamap;

    jose_recipients_t recipients;  // per "alg"

    _jose_encryption_t() : enc_info(nullptr) {}
} jose_encryption_t;
typedef std::map<jwe_t, jose_encryption_t> jose_encryptions_map_t;
typedef std::pair<jose_encryptions_map_t::iterator, bool> jose_encryptions_map_pib_t;

/* JWS */
typedef struct _jose_sign_t {
    std::string header;
    std::string payload;
    std::string signature;
    std::string kid;
    jws_t sig;
} jose_sign_t;
typedef std::list<jose_sign_t> jose_signs_t;

typedef struct _jose_context_t {
    crypto_key* key;

    uint32 flags;
    binary_t protected_header;  // compact, flat

    jose_encryptions_map_t encryptions;  // JSON Object Encryption
    jose_signs_t signs;                  // JSON Object Signing

    _jose_context_t() : key(nullptr), flags(0) {}
} jose_context_t;

class json_object_encryption;
class json_object_signing;
class json_object_signing_encryption;
class json_web_key;
class json_web_signature;
typedef json_object_signing_encryption JOSE;

}  // namespace crypto
}  // namespace hotplace

#endif
