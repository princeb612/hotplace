/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_JOSE_TYPES__
#define __HOTPLACE_SDK_CRYPTO_JOSE_TYPES__

#include <hotplace/sdk/crypto/types.hpp>
#include <hotplace/sdk/crypto/openssl/types.hpp>
#include <hotplace/sdk/crypto/openssl/crypto_key.hpp>
#include <list>
#include <map>

namespace hotplace {
namespace crypto {

enum jose_serialization_t {
    JOSE_COMPACT    = 0,
    JOSE_JSON       = 1,
    JOSE_FLATJSON   = 2,
};
#define JOSE_JSON_FORMAT JOSE_FLATJSON

enum jose_compose_t {
    JOSE_HEADER_ENC_ONLY    = 1,
    JOSE_HEADER_ALG_ONLY    = 2,
    JOSE_HEADER_ENC_ALG     = 3,
};

enum jose_type_t {
    jose_alg_signature              = 1,
    jose_alg_key_management         = 2,
    jose_alg_contente_encryption    = 3,
};

enum jose_part_t {
    ENCRYPTION_PART = 1,
    ALGORITHM_PART  = 2,
};

typedef struct _jose_recipient_t {
    const hint_jose_encryption_t* alg_info;
    EVP_PKEY* pkey;

    std::string header;
    std::string kid;

    crypt_datamap_t datamap;
    crypt_variantmap_t variantmap; // p2c, epk
    EVP_PKEY* epk;
    uint32 p2c;

    /* IV, TAG case of A128GCMKW, A192GCMKW, A256GCMKW */
    /* P2S, P2C case of PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW */
    /* EPK, APU, APV case of ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW */

    _jose_recipient_t () : alg_info (nullptr), pkey (nullptr), epk (nullptr), p2c (0)
    {
        // do nothing
    }
} jose_recipient_t;
typedef std::map<jwa_t, jose_recipient_t> jose_recipients_t;
typedef std::pair<jose_recipients_t::iterator, bool> jose_recipients_pib_t;

/*
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

    jose_recipients_t recipients; // per "alg"

    _jose_encryption_t () : enc_info (nullptr)
    {
        // do nothing
    }
}  jose_encryption_t;
typedef std::map<jwe_t, jose_encryption_t> jose_encryptions_t;
typedef std::pair<jose_encryptions_t::iterator, bool> jose_encryptions_pib_t;

/* JWS */
typedef struct _jose_sign_t {
    std::string header;
    std::string payload;
    std::string signature;
    std::string kid;
    jws_t sig;
} jose_sign_t;
typedef std::list<jose_sign_t> jose_signs_t;

struct _jose_context_t {};
typedef struct _jose_context_t jose_context_t;

typedef struct _JOSE_CONTEXT : _jose_context_t {
    crypto_key* key;

    binary_t protected_header;      // compact, flat

    jose_encryptions_t encryptions; // JSON Object Encryption
    jose_signs_t signs;             // JSON Object Signing

    _JOSE_CONTEXT () : key (nullptr)
    {
        // do nothing
    }
} JOSE_CONTEXT;

}
}  // namespace

#endif
