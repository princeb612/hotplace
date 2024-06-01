/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 7515 JSON Web Signature (JWS)
 *  RFC 7516 JSON Web Encryption (JWE)
 *  RFC 7517 JSON Web Key (JWK)
 *  RFC 7518 JSON Web Algorithms (JWA)
 *  RFC 7520 Examples of Protecting Content Using JSON Object Signing and Encryption (JOSE)
 *  RFC 8037 CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)
 *
 *  implementation status
 *  Cryptographic Algorithms for Digital Signatures and MACs
 *  +---+--------------+-------------------------------+--------------------+
 *  |   | "alg" Param  | Digital Signature or MAC      | Implementation     |
 *  |   | Value        | Algorithm                     | Requirements       |
 *  + --+--------------+-------------------------------+--------------------+
 *  | O | HS256        | HMAC using SHA-256            | Required           |
 *  | O | HS384        | HMAC using SHA-384            | Optional           |
 *  | O | HS512        | HMAC using SHA-512            | Optional           |
 *  | O | RS256        | RSASSA-PKCS1-v1_5 using       | Recommended        |
 *  |   |              | SHA-256                       |                    |
 *  | O | RS384        | RSASSA-PKCS1-v1_5 using       | Optional           |
 *  |   |              | SHA-384                       |                    |
 *  | O | RS512        | RSASSA-PKCS1-v1_5 using       | Optional           |
 *  |   |              | SHA-512                       |                    |
 *  | O | ES256        | ECDSA using P-256 and SHA-256 | Recommended+       |
 *  | O | ES384        | ECDSA using P-384 and SHA-384 | Optional           |
 *  | O | ES512        | ECDSA using P-521 and SHA-512 | Optional           |
 *  | O | PS256        | RSASSA-PSS using SHA-256 and  | Optional           |
 *  |   |              | MGF1 with SHA-256             |                    |
 *  | O | PS384        | RSASSA-PSS using SHA-384 and  | Optional           |
 *  |   |              | MGF1 with SHA-384             |                    |
 *  | O | PS512        | RSASSA-PSS using SHA-512 and  | Optional           |
 *  |   |              | MGF1 with SHA-512             |                    |
 *  |   | none         | No digital signature or MAC   | Optional           |
 *  |   |              | performed                     |                    |
 *  | O | EdDSA        | RFC 8037                      |                    |
 *  +---+--------------+-------------------------------+--------------------+
 *  Cryptographic Algorithms for Key Management
 *  +---+--------------------+--------------------+--------+----------------+
 *  |   | "alg" Param Value  | Key Management     | More   | Implementation |
 *  |   |                    | Algorithm          | Header | Requirements   |
 *  |   |                    |                    | Params |                |
 *  +---+--------------------+--------------------+--------+----------------+
 *  | O | RSA1_5             | RSAES-PKCS1-v1_5   | (none) | Recommended-   |
 *  | O | RSA-OAEP           | RSAES OAEP using   | (none) | Recommended+   |
 *  |   |                    | default parameters |        |                |
 *  | O | RSA-OAEP-256       | RSAES OAEP using   | (none) | Optional       |
 *  |   |                    | SHA-256 and MGF1   |        |                |
 *  |   |                    | with SHA-256       |        |                |
 *  | O | A128KW             | AES Key Wrap with  | (none) | Recommended    |
 *  |   |                    | default initial    |        |                |
 *  |   |                    | value using        |        |                |
 *  |   |                    | 128-bit key        |        |                |
 *  | O | A192KW             | AES Key Wrap with  | (none) | Optional       |
 *  |   |                    | default initial    |        |                |
 *  |   |                    | value using        |        |                |
 *  |   |                    | 192-bit key        |        |                |
 *  | O | A256KW             | AES Key Wrap with  | (none) | Recommended    |
 *  |   |                    | default initial    |        |                |
 *  |   |                    | value using        |        |                |
 *  |   |                    | 256-bit key        |        |                |
 *  | O | dir                | Direct use of a    | (none) | Recommended    |
 *  |   |                    | shared symmetric   |        |                |
 *  |   |                    | key as the CEK     |        |                |
 *  | O | ECDH-ES            | Elliptic Curve     | "epk", | Recommended+   |
 *  |   |                    | Diffie-Hellman     | "apu", |                |
 *  |   |                    | Ephemeral Static   | "apv"  |                |
 *  |   |                    | key agreement      |        |                |
 *  |   |                    | using Concat KDF   |        |                |
 *  | O | ECDH-ES+A128KW     | ECDH-ES using      | "epk", | Recommended    |
 *  |   |                    | Concat KDF and CEK | "apu", |                |
 *  |   |                    | wrapped with       | "apv"  |                |
 *  |   |                    | "A128KW"           |        |                |
 *  | O | ECDH-ES+A192KW     | ECDH-ES using      | "epk", | Optional       |
 *  |   |                    | Concat KDF and CEK | "apu", |                |
 *  |   |                    | wrapped with       | "apv"  |                |
 *  |   |                    | "A192KW"           |        |                |
 *  | O | ECDH-ES+A256KW     | ECDH-ES using      | "epk", | Recommended    |
 *  |   |                    | Concat KDF and CEK | "apu", |                |
 *  |   |                    | wrapped with       | "apv"  |                |
 *  |   |                    | "A256KW"           |        |                |
 *  | O | A128GCMKW          | Key wrapping with  | "iv",  | Optional       |
 *  |   |                    | AES GCM using      | "tag"  |                |
 *  |   |                    | 128-bit key        |        |                |
 *  | O | A192GCMKW          | Key wrapping with  | "iv",  | Optional       |
 *  |   |                    | AES GCM using      | "tag"  |                |
 *  |   |                    | 192-bit key        |        |                |
 *  | O | A256GCMKW          | Key wrapping with  | "iv",  | Optional       |
 *  |   |                    | AES GCM using      | "tag"  |                |
 *  |   |                    | 256-bit key        |        |                |
 *  | O | PBES2-HS256+A128KW | PBES2 with HMAC    | "p2s", | Optional       |
 *  |   |                    | SHA-256 and        | "p2c"  |                |
 *  |   |                    | "A128KW" wrapping  |        |                |
 *  | O | PBES2-HS384+A192KW | PBES2 with HMAC    | "p2s", | Optional       |
 *  |   |                    | SHA-384 and        | "p2c"  |                |
 *  |   |                    | "A192KW" wrapping  |        |                |
 *  | O | PBES2-HS512+A256KW | PBES2 with HMAC    | "p2s", | Optional       |
 *  |   |                    | SHA-512 and        | "p2c"  |                |
 *  |   |                    | "A256KW" wrapping  |        |                |
 *  +---+--------------------+--------------------+--------+----------------+
 *  Cryptographic Algorithms for Content Encryption
 *  +---+---------------+----------------------------------+----------------+
 *  |   | "enc" Param   | Content Encryption Algorithm     | Implementation |
 *  |   | Value         |                                  | Requirements   |
 *  +---+---------------+----------------------------------+----------------+
 *  | O | A128CBC-HS256 | AES_128_CBC_HMAC_SHA_256         | Required       |
 *  |   |               | authenticated encryption         |                |
 *  |   |               | algorithm, as defined in Section |                |
 *  |   |               | 5.2.3                            |                |
 *  | O | A192CBC-HS384 | AES_192_CBC_HMAC_SHA_384         | Optional       |
 *  |   |               | authenticated encryption         |                |
 *  |   |               | algorithm, as defined in Section |                |
 *  |   |               | 5.2.4                            |                |
 *  | O | A256CBC-HS512 | AES_256_CBC_HMAC_SHA_512         | Required       |
 *  |   |               | authenticated encryption         |                |
 *  |   |               | algorithm, as defined in Section |                |
 *  |   |               | 5.2.5                            |                |
 *  | O | A128GCM       | AES GCM using 128-bit key        | Recommended    |
 *  | O | A192GCM       | AES GCM using 192-bit key        | Optional       |
 *  | O | A256GCM       | AES GCM using 256-bit key        | Recommended    |
 *  +---+---------------+----------------------------------+----------------+
 *  JWK
 *  +---+---------------+----------------------------------+----------------+
 *  |   | kty           |                                  |                |
 *  +---+---------------+----------------------------------+----------------+
 *  | O | oct           | JWK/PEM(openssl 1.1.1)           |                |
 *  | O | RSA           | JWK/PEM                          |                |
 *  | O | EC            | JWK/PEM                          |                |
 *  |   |               | crv "P-256","P-384","P-521"      |                |
 *  | O | OKP           | RFC 8037                         |                |
 *  |   |               | JWK/PEM                          |                |
 *  |   |               | crv "Ed25519","Ed448"            |                |
 *  | O |               | crv "X25519","X448"              |                |
 *  +---+---------------+----------------------------------+----------------+
 *
 * Revision History
 * Date         Name                Description
 * 2017.10.30   Soo Han, Kim        RFC 7515 A.1 (codename.grape)
 *                                  JWS HS256,HS384,HS512,RS256,RS384,RS512
 * 2017.11.30   Soo Han, Kim        RFC 7516 Appendix B.  Example AES_128_CBC_HMAC_SHA_256 Computation (codename.grape)
 * 2017.12.06   Soo Han, Kim        RFC 7516 decryption (codename.grape)
 *                                  JWE RSA-OAEP,RSA-OAEP-256,RSA1_5,A128KW,A192KW,A256KW
 *                                  JWA A128GCM,A192GCM,A256GCM,A128CBC-HS256,A192CBC-HS384,A256CBC-HS512
 * 2018.11.15   Soo Han, Kim        RFC 7515 A.3. A.4. (codename.grape)
 *                                  JWS ES256,ES384,ES512
 * 2018.11.20   Soo Han, Kim        RFC7517 Example C (codename.grape)
 *                                  JWE PBES2-HS256+A128KW
 * 2018.11.21   Soo Han, Kim        RFC 7517 Appendix C.  Example Encrypted RSA Private Key (codename.grape)
 * 2018.12.07   Soo Han, Kim        RFC 7516 A.4.   (codename.grape)
 *                                  PBES2-HS384+A192KW, PBES2-HS512+A256KW
 * 2019.01.01   Soo Han, Kim        RFC 7518 RSASSA-PSS using SHA-256 and MGF1 with SHA-256 (JWS PS256,PS384,PS512) (codename.grape)
 * 2019.01.01   Soo Han, Kim        JWE (codename.grape)
 *                                  ECDH-ES,ECDH-ES+A128KW,ECDH-ES+A192KW,ECDH-ES+A256KW
 * 2021.01.23   Soo Han, Kim        RFC 8037 (codename.unicorn)
 *                                  JWS EdDSA
 *                                  JWK OKP
 * 2022.05.18   Soo Han, Kim        apply openssl 3 (codename.unicorn)
 *
 */

#ifndef __HOTPLACE_SDK_CRYPTO_JOSE__
#define __HOTPLACE_SDK_CRYPTO_JOSE__

#include <sdk/crypto/basic/types.hpp>
#include <sdk/crypto/jose/types.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief JSON Object Signing and Encryption
 * @remarks
 *  JOSE - json serialization
 *  json_object_encryption - implementation of encryption
 *  json_object_signing - implementation of signing
 */
class json_object_signing_encryption {
    friend class json_object_encryption;

   public:
    json_object_signing_encryption();
    ~json_object_signing_encryption();

    /**
     * @brief open
     * @param jose_context_t** context [out]
     * @param crypto_key* crypto_key [in]
     * @return error code (see error.hpp)
     */
    return_t open(jose_context_t** context, crypto_key* crypto_key);
    /**
     * @brief close
     * @param jose_context_t* context [in]
     * @return error code (see error.hpp)
     */
    return_t close(jose_context_t* context);

    /**
     * @brief option
     * @param jose_context_t* context [in]
     * @param uint32 flags [in] see jose_flag_t
     * @return error code (see error.hpp)
     */
    return_t setoption(jose_context_t* context, uint32 flags);

    /**
     * @brief encrypt
     * @param jose_context_t* context [in]
     * @param jwe_t enc [in]
     * @param jwa_t alg [in] support all algorithms including jwa_t::jwa_dir, jwa_t::jwa_ecdh_es
     * @param const binary_t& input [in]
     * @param std::string& output [out]
     * @param jose_serialization_t type [inopt]
     * @return error code (see error.hpp)
     * @example
     *          json_web_key jwk;
     *          crypto_key crypto_pubkey;
     *          crypto_key crypto_privkey;
     *          jwk.load_file (&crypto_pubkey, "rfc7520_pub.jwk", 0);
     *          jwk.load_file (&crypto_privkey, "rfc7520_priv.jwk", 0);
     *
     *          json_object_signing_encryption jose;
     *          jose_context_t* handle_encrypt = nullptr;
     *          jose_context_t* handle_decrypt = nullptr;
     *          jose.open (&handle_encrypt, &crypto_pubkey);
     *          jose.open (&handle_decrypt, &crypto_privkey);
     *          ret = jose.encrypt (handle_encrypt, jwe_t::jwe_a128cbc_hs256, jwa_t::jwa_ecdh_es, tostring (input), encrypted, jose_serialization_t::jose_json);
     *          ret = jose.decrypt (handle_decrypt, encrypted, output, result);
     *          jose.close (handle_encrypt);
     *          jose.close (handle_decrypt);
     */
    return_t encrypt(jose_context_t* context, jwe_t enc, jwa_t alg, const binary_t& input, std::string& output,
                     jose_serialization_t type = jose_serialization_t::jose_compact);
    /**
     * @brief encrypt
     * @param jose_context_t* context [in]
     * @param jwe_t enc [in]
     * @param std::list <jwa_t> alg [in]
     *  do not support jwa_t::jwa_dir, jwa_t::jwa_ecdh_es
     *  case "dir"
     *      read cek from HMAC key and then make it the only one cek
     *      protected, iv, ciphertext, tag, recipients:[ header {alg:dir}, encrypted_key(empty) ]
     *
     *  case "ECDH-ES"
     *      read cek using ECDH-ES
     *      protected, iv, ciphertext, tag, recipients:[ header {alg:ECDH-ES, epk}, encrypted_key ]
     * @param const binary_t& input [in]
     * @param std::string& output [out]
     * @param jose_serialization_t type [inopt]
     * @return error code (see error.hpp)
     * @example
     *          json_web_key jwk;
     *          crypto_key crypto_pubkey;
     *          jwk.load_file (&crypto_pubkey, "rfc7520_pub.jwk", 0);
     *
     *          json_object_signing_encryption jose;
     *          jose_context_t* handle_encrypt = nullptr;
     *          jose.open (&handle_encrypt, &crypto_pubkey);
     *          std::list<jwa_t> algs;
     *          algs.push_back (jwa_t::jwa_rsa_1_5);
     *          algs.push_back (jwa_t::jwa_rsa_oaep);
     *          algs.push_back (jwa_t::jwa_rsa_oaep_256);
     *          algs.push_back (jwa_t::jwa_a128kw);
     *          algs.push_back (jwa_t::jwa_a192kw);
     *          algs.push_back (jwa_t::jwa_a256kw);
     *          algs.push_back (jwa_t::jwa_ecdh_es_a128kw);
     *          algs.push_back (jwa_t::jwa_ecdh_es_a192kw);
     *          algs.push_back (jwa_t::jwa_ecdh_es_a256kw);
     *          algs.push_back (jwa_t::jwa_a128gcmkw);
     *          algs.push_back (jwa_t::jwa_a192gcmkw);
     *          algs.push_back (jwa_t::jwa_a256gcmkw);
     *          algs.push_back (jwa_t::jwa_pbes2_hs256_a128kw);
     *          algs.push_back (jwa_t::jwa_pbes2_hs384_a192kw);
     *          algs.push_back (jwa_t::jwa_pbes2_hs512_a256kw);
     *          ret = jose.encrypt (handle_encrypt, jwe_t::jwe_a128cbc_hs256, algs, tostring (input), encrypted, jose_serialization_t::jose_json);
     *          jose.close (handle_encrypt);
     */
    return_t encrypt(jose_context_t* context, jwe_t enc, std::list<jwa_t> algs, const binary_t& input, std::string& output,
                     jose_serialization_t type = jose_serialization_t::jose_compact);
    /**
     * @brief decrypt
     * @param jose_context_t* context [in]
     * @param const std::string& input [in]
     * @param binary_t& output [out]
     * @param bool& result [out]
     * @return error code (see error.hpp)
     * @example
     *          json_web_key jwk;
     *          crypto_key crypto_privkey;
     *          jwk.load_file (&crypto_privkey, "rfc7520_priv.jwk", 0);
     *
     *          json_object_signing_encryption jose;
     *          jose_context_t* handle_decrypt = nullptr;
     *          jose.open (&handle_decrypt, &crypto_privkey);
     *          ret = jose.decrypt (handle_decrypt, encrypted, output, result);
     *          jose.close (handle_decrypt);
     */
    return_t decrypt(jose_context_t* context, const std::string& input, binary_t& output, bool& result);
    /**
     * @brief sign
     * @param jose_context_t* context [in]
     * @param jws_t method [in]
     * @param const std::string& input [in]
     * @param std::string& output [out]
     * @param jose_serialization_t type [inopt]
     * @return error code (see error.hpp)
     * @example
     *          json_web_key jwk;
     *          crypto_key crypto_key;
     *          jwk.load_file (&crypto_key, "rfc7515.jwk", 0);
     *          json_object_signing_encryption jose;
     *          bool result = false;
     *          std::string jws_result;
     *
     *          jose_context_t* jose_context = nullptr;
     *          jose.open (&jose_context, &crypto_key);
     *          jose.sign (jose_context, jws_t::jws_hs256, claim, jws_result);
     *          jose.verify (jose_context, jws_result, result);
     *          jose.close (jose_context);
     */
    return_t sign(jose_context_t* context, jws_t method, const std::string& input, std::string& output,
                  jose_serialization_t type = jose_serialization_t::jose_compact);
    /**
     * @brief sign
     * @param jose_context_t* context [in]
     * @param std::list <jws_t> const& methods [in]
     * @param const std::string& input [in]
     * @param std::string& output [out]
     * @param jose_serialization_t type [inopt]
     * @return error code (see error.hpp)
     * @example
     *          json_web_key jwk;
     *          crypto_key crypto_key;
     *          jwk.load_file (&crypto_key, "rfc7515.jwk", 0);
     *          json_object_signing_encryption jose;
     *          bool result = false;
     *          std::string jws_result;
     *          std::list <jws_t> methods;
     *          methods.push_back (jws_t::jws_hs256);
     *          methods.push_back (jws_t::jws_rs256);
     *          methods.push_back (jws_t::jws_es256);
     *
     *          jose_context_t* jose_context = nullptr;
     *          jose.open (&jose_context, &crypto_key);
     *          jose.sign (jose_context, methods, claim, jws_result);
     *          jose.verify (jose_context, jws_result, result);
     *          jose.close (jose_context);
     */
    return_t sign(jose_context_t* context, std::list<jws_t> const& methods, const std::string& input, std::string& output,
                  jose_serialization_t type = jose_serialization_t::jose_compact);
    /**
     * @brief sign
     * @param jose_context_t* context [in]
     * @param const std::string& protected_header [in]
     * @param const std::string& input [in]
     * @param std::string& output [out]
     * @param jose_serialization_t type [inopt]
     * @return error code (see error.hpp)
     * @example
     *          json_web_key jwk;
     *          crypto_key crypto_key;
     *          jwk.load_file (&crypto_key, "rfc7515.jwk", 0);
     *          json_object_signing_encryption jose;
     *          bool result = false;
     *          std::string jws_result;
     *
     *          jose_context_t* jose_context = nullptr;
     *          jose.open (&jose_context, &crypto_key);
     *          jose.sign (jose_context, (char*) hs256_header, claim, jws_result);
     *          jose.verify (jose_context, jws_result, result);
     *          jose.close (jose_context);
     */
    return_t sign(jose_context_t* context, const std::string& protected_header, const std::string& input, std::string& output,
                  jose_serialization_t type = jose_serialization_t::jose_compact);
    /**
     * @brief sign
     * @param jose_context_t* context [in]
     * @param std::list<std::string> const& headers [in]
     * @param const std::string& input [in]
     * @param std::string& output [out]
     * @param jose_serialization_t type [inopt]
     * @return error code (see error.hpp)
     */
    return_t sign(jose_context_t* context, std::list<std::string> const& headers, const std::string& input, std::string& output,
                  jose_serialization_t type = jose_serialization_t::jose_compact);
    /**
     * @brief verify
     * @param jose_context_t* context [in]
     * @param const std::string& input [in]
     * @param bool& result [out]
     * @return error code (see error.hpp)
     */
    return_t verify(jose_context_t* context, const std::string& input, bool& result);

    /**
     * @brief clear/reset
     * @param jose_context_t* context [in]
     */
    static return_t clear_context(jose_context_t* context);
};

typedef json_object_signing_encryption JOSE;

}  // namespace crypto
}  // namespace hotplace

#endif
