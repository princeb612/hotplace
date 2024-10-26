/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_OPENSSL_CRYPTOADVISOR__
#define __HOTPLACE_SDK_CRYPTO_OPENSSL_CRYPTOADVISOR__

#include <algorithm>
#include <functional>
#include <map>
#include <sdk/base/unittest/traceable.hpp>
#include <sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

enum advisor_feature_t {
    advisor_feature_cipher = (1 << 0),
    advisor_feature_md = (1 << 1),
    advisor_feature_wrap = (1 << 2),
    advisor_feature_jwa = (1 << 3),
    advisor_feature_jwe = (1 << 4),
    advisor_feature_jws = (1 << 5),
    advisor_feature_cose = (1 << 6),
    advisor_feature_curve = (1 << 7),
    advisor_feature_version = (1 << 8),
    advisor_feature_unspecified = (1 << 9),
};

/**
 * @brief   advisor
 * @sample
 *          auto lambda = [&](trace_category_t, uint32, stream_t* s) -> void { do_somgthing(); };
 *          crypto_advisor::trace(lambda);
 *          auto advisor = crypto_advisor::get_instance();
 */
class crypto_advisor : public traceable {
   public:
    static crypto_advisor* get_instance();

    ~crypto_advisor();

    /**
     * @brief find blockcipher hint
     * @param crypt_algorithm_t alg [in]
     * @return hint_blockcipher_t*
     * @remarks EVP_CIPHER_CTX_block_size works wrong ?
     * @example
     *      crypto_advisor* advisor = crypto_advisor::get_instance ();
     *      const hint_blockcipher_t* blockcipher = advisor->hintof_blockcipher (crypt_algorithm_t::aes256);
     *      size_t keysize = sizeof_key(blockcipher);
     *      size_t ivsize = sizeof_iv(blockcipher);
     *      size_t blocksize = sizeof_block(blockcipher);
     */
    const hint_blockcipher_t* hintof_blockcipher(crypt_algorithm_t alg);
    const hint_blockcipher_t* hintof_blockcipher(const char* alg);
    /**
     * @brief find blockcipher hint
     * @param const EVP_CIPHER* cipher [in]
     */
    const hint_blockcipher_t* find_evp_cipher(const EVP_CIPHER* cipher);

    /**
     * @brief find cipher method
     * @param crypt_algorithm_t algorithm [in] crypt_algorithm_t
     * @param crypt_mode_t mode [in] crypt_mode_t
     * @return EVP_CIPHER*
     * @remarks
     *          const EVP_CIPHER* aes_128_cbc = find_evp_cipher (crypt_algorithm_t::aes128, crypt_mode_t::cbc); // EVP_aes_128_cbc ()
     *
     *          can be nullptr
     *          for example, seed deprecated since openssl 3.0
     */
    const EVP_CIPHER* find_evp_cipher(crypt_algorithm_t algorithm, crypt_mode_t mode);
    const EVP_CIPHER* find_evp_cipher(const char* name);
    /**
     * @brief hint
     * @param const char* name [in] ex. "aes-128-cbc"
     */
    const hint_cipher_t* hintof_cipher(const char* name);
    /**
     * @brief hint
     * @param const EVP_CIPHER* cipher [in]
     */
    const hint_cipher_t* hintof_cipher(const EVP_CIPHER* cipher);
    /**
     * @brief find cipher string
     * @param crypt_algorithm_t algorithm [in] crypt_algorithm_t
     * @param crypt_mode_t mode [in] crypt_mode_t
     * @return const char*
     * @remarks
     *          const char* cipher_string = advisor->nameof_cipher (crypt_algorithm_t::aes128, crypt_mode_t::cbc);
     *          // return "aes-128-cbc"
     *          EVP_CIPHER* evp_cipher = EVP_CIPHER_fetch ("aes-128-cbc", nullptr);
     *          // return EVP_aes_128_cbc ()
     */
    const char* nameof_cipher(crypt_algorithm_t algorithm, crypt_mode_t mode);
    /**
     * @brief find md method
     * @param hash_algorithm_t algorithm [in] hash_algorithm_t
     * @return EVP_MD*
     * @remarks
     *          const EVP_MD* sha3_512 = (const EVP_MD*) find_evp_md (hash_algorithm_t::sha3_512); // EVP_sha3_512 ()
     */
    const EVP_MD* find_evp_md(hash_algorithm_t algorithm);
    const EVP_MD* find_evp_md(crypt_sig_t sig);
    const EVP_MD* find_evp_md(jws_t sig);
    const EVP_MD* find_evp_md(const char* name);
    const hint_digest_t* hintof_digest(hash_algorithm_t algorithm);
    const hint_digest_t* hintof_digest(const char* name);
    hash_algorithm_t get_algorithm(crypt_sig_t sig);
    hash_algorithm_t get_algorithm(jws_t sig);
    /**
     * @brief find md string
     * @param hash_algorithm_t algorithm [in] hash_algorithm_t
     * @return const char*
     * @remarks
     *          const char* md_string = advisor->nameof_md (hash_algorithm_t::sha3_256);
     *          // return "sha3-256"
     *          EVP_MD* evp_md = EVP_MD_fetch (nullptr, "sha3-256", nullptr);
     *          // return EVP_sha3_256 ()
     */
    const char* nameof_md(hash_algorithm_t algorithm);

    return_t cipher_for_each(std::function<void(const char*, uint32, void*)> f, void* user);
    return_t md_for_each(std::function<void(const char*, uint32, void*)> f, void* user);
    /**
     * @brief   iteration helper methods  - algoritm encrypton signature
     * @example
     *          crypto_advisor* advisor = crypto_advisor::get_instance ();
     *
     *          std::function <void (const hint_jose_encryption_t*, void*)> lambda1 =
     *                  [] (const hint_jose_encryption_t* item, void* user) -> void { printf ("    %s\n", item->alg_name); };
     *          std::function <void (const hint_signature_t*, void*)> lambda2 =
     *                  [] (const hint_signature_t* item, void* user) -> void { printf ("    %s\n", item->jws_name); };
     *
     *          advisor->jose_for_each_algorithm (lambda1, nullptr );
     *          advisor->jose_for_each_encryption (lambda1, nullptr );
     *
     *          advisor->jose_for_each_signature (lambda2, nullptr );
     */
    return_t jose_for_each_algorithm(std::function<void(const hint_jose_encryption_t*, void*)> f, void* user);
    return_t jose_for_each_encryption(std::function<void(const hint_jose_encryption_t*, void*)> f, void* user);
    return_t jose_for_each_signature(std::function<void(const hint_signature_t*, void*)> f, void* user);
    return_t cose_for_each(std::function<void(const char*, uint32, void*)> f, void* user);
    return_t curve_for_each(std::function<void(const char*, uint32, void*)> f, void* user);

    /**
     * @brief hint
     * @param jwa_t alg [in]
     *          jwa_t::jwa_rsa_1_5, jwa_t::jwa_rsa_oaep, jwa_t::jwa_rsa_oaep_256,jwa_t::jwa_a128kw series,
     *          jwa_t::jwa_ecdh_es, jwa_t::jwa_ecdh_es_a128kw series,
     *          jwa_t::jwa_a128gcmkw series, jwa_t::jwa_pbes2_hs256_a128kw series
     * @return const hint_jose_encryption_t*
     * @example
     *          const hint_jose_encryption_t* alg_info = advisor->hintof_jose_algorithm (alg);
     */
    const hint_jose_encryption_t* hintof_jose_algorithm(jwa_t alg);
    /**
     * @brief hint
     * @param jwe_t enc [in]
     *          jwe_t::jwe_a128cbc_hs256 series, jwe_t::jwe_a128gcm series
     * @return const hint_jose_encryption_t*
     * @example
     *          const hint_jose_encryption_t* enc_info = advisor->hintof_jose_encryption (enc);
     */
    const hint_jose_encryption_t* hintof_jose_encryption(jwe_t enc);
    /**
     * @brief hint
     * @param crypt_sig_t sig [in]
     *          crypt_sig_t::hs256 series, crypt_sig_t::rs256 series, crypt_sig_t::es256 series, crypt_sig_t::ps256 series, crypt_sig_t::eddsa
     * @return const hint_signature_t*
     */
    const hint_signature_t* hintof_signature(crypt_sig_t sig);
    /**
     * @brief hint
     * @param jws_t sig [in]
     *          jws_t::jws_hs256 series, jws_t::jws_rs256 series, jws_t::jws_es256 series, jws_t::jws_ps256 series, jws_t::jws_eddsa
     * @return const hint_signature_t*
     */
    const hint_signature_t* hintof_jose_signature(jws_t sig);
    /**
     * @brief hint
     * @param cose_alg_t sig [in]
     * @return const hint_cose_algorithm_t*
     */
    const hint_cose_algorithm_t* hintof_cose_algorithm(cose_alg_t alg);
    /**
     * @brief hint
     * @param uint32 nid [in] see ec_curve_t
     *          NID_X9_62_prime256v1, NID_secp384r1, NID_secp521r1, NID_ED25519, NID_ED448, NID_X25519, NID_X448
     * @return const hint_curve_t*
     * @sa hintof_curve
     */
    const hint_curve_t* hintof_curve_nid(uint32 nid);
    const hint_curve_t* hintof_curve(cose_ec_curve_t curve);
    /**
     * @brief hint
     * @param const char* alg [in]
     *          "RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
     *          "A128KW" series,
     *          "ECDH-ES", "ECDH-ES+A128KW" series,
     *          "A128GCMKW" series,
     *          "PBES2-HS256+A128KW" series
     * @return const hint_jose_encryption_t*
     */
    const hint_jose_encryption_t* hintof_jose_algorithm(const char* alg);
    /**
     * @brief hint
     * @param const char* enc [in]
     *          "A128CBC-HS256" series, "A128GCM" series
     * @return const hint_jose_encryption_t*
     */
    const hint_jose_encryption_t* hintof_jose_encryption(const char* enc);
    /**
     * @brief hint
     * @param const char* sig [in]
     *          "HS256" series, "RS256" series, "ES256" series, "PS256" series, "EdDSA"
     * @return const hint_signature_t*
     */
    const hint_signature_t* hintof_jose_signature(const char* sig);
    /**
     * @brief hint
     * @param const char* alg [in]
     * @return const hint_cose_algorithm_t*
     */
    const hint_cose_algorithm_t* hintof_cose_algorithm(const char* alg);
    /**
     * @brief hint
     * @param const char* curve [in]
     *          "P-256" series, "Ed25519", "Ed448", "X25519", "X448"
     * @return const hint_curve_t*
     * @sa hintof_curve_nid
     */
    const hint_curve_t* hintof_curve(const char* curve);

    /**
     * @brief JWA
     * @param jwa_t alg [in]
     * @return
     *          RSA1_5
     *          RSA-OAEP
     *          RSA-OAEP-256
     *          A128KW
     *          A192KW
     *          A256KW
     *          dir
     *          ECDH-ES
     *          ECDH-ES+A128KW
     *          ECDH-ES+A192KW
     *          ECDH-ES+A256KW
     *          A128GCMKW
     *          A192GCMKW
     *          A256GCMKW
     *          PBES2-HS256+A128KW
     *          PBES2-HS384+A192KW
     *          PBES2-HS512+A256KW
     */
    const char* nameof_jose_algorithm(jwa_t alg);
    /**
     * @brief JWE
     * @param jwe_t enc [in]
     * @return
     *          A128CBC-HS256
     *          A192CBC-HS384
     *          A256CBC-HS512
     *          A128GCM
     *          A192GCM
     *          A256GCM
     */
    const char* nameof_jose_encryption(jwe_t enc);
    /**
     * @brief JWS
     * @param jws_t enc [in]
     * @return
     *          HS256
     *          HS384
     *          HS512
     *          RS256
     *          RS384
     *          RS512
     *          ES256
     *          ES384
     *          ES512
     *          PS256
     *          PS384
     *          PS512
     *          EdDSA
     */
    const char* nameof_jose_signature(jws_t sig);
    /**
     * @brief COSE (name decribed in RFC)
     */
    const char* nameof_cose_algorithm(cose_alg_t alg);

    /**
     * @brief type
     * @param const char* alg [in]
     * @param jwa_t& type [out]
     * @remarks
     *          --------------------+-----------------------------
     *          "RSA1_5"            | jwa_t::jwa_rsa_1_5
     *          "RSA-OAEP"          | jwa_t::jwa_rsa_oaep
     *          "RSA-OAEP-256"      | jwa_t::jwa_rsa_oaep_256
     *          "A128KW"            | jwa_t::jwa_a128kw
     *          "A192KW"            | jwa_t::jwa_a192kw
     *          "A256KW"            | jwa_t::jwa_a256kw
     *          "dir"               | jwa_t::jwa_dir
     *          "ECDH-ES"           | jwa_t::jwa_ecdh_es
     *          "ECDH-ES+A128KW"    | jwa_t::jwa_ecdh_es_a128kw
     *          "ECDH-ES+A192KW"    | jwa_t::jwa_ecdh_es_a192kw
     *          "ECDH-ES+A256KW"    | jwa_t::jwa_ecdh_es_a256kw
     *          "A128GCMKW"         | jwa_t::jwa_a128gcmkw
     *          "A192GCMKW"         | jwa_t::jwa_a192gcmkw
     *          "A256GCMKW"         | jwa_t::jwa_a256gcmkw
     *          "PBES2-HS256+A128KW"| jwa_t::jwa_pbes2_hs256_a128kw
     *          "PBES2-HS384+A192KW"| jwa_t::jwa_pbes2_hs384_a192kw
     *          "PBES2-HS512+A256KW"| jwa_t::jwa_pbes2_hs512_a256kw
     *          --------------------+-----------------------------
     */
    return_t typeof_jose_algorithm(const char* alg, jwa_t& type);
    /**
     * @brief type
     * @param const char* enc [in]
     * @param jwe_t& type [out]
     * @remarks
     *          --------------------+------------------------
     *          "A128CBC-HS256"     | jwe_t::jwe_a128cbc_hs256
     *          "A192CBC-HS384"     | jwe_t::jwe_a192cbc_hs384
     *          "A256CBC-HS512"     | jwe_t::jwe_a256cbc_hs512
     *          "A128GCM"           | jwe_t::jwe_a128gcm
     *          "A192GCM"           | jwe_t::jwe_a192gcm
     *          "A256GCM"           | jwe_t::jwe_a256gcm
     *          --------------------+------------------------
     */
    return_t typeof_jose_encryption(const char* enc, jwe_t& type);
    /**
     * @brief type
     * @param const char* sig [in]
     * @param jws_t& type [out]
     * @remarks
     *          --------------------+-----------
     *          "HS256"             | jws_t::jws_hs256
     *          "HS384"             | jws_t::jws_hs384
     *          "HS512"             | jws_t::jws_hs512
     *          "RS256"             | jws_t::jws_rs256
     *          "RS384"             | jws_t::jws_rs384
     *          "RS512"             | jws_t::jws_rs512
     *          "ES256"             | jws_t::jws_es256
     *          "ES384"             | jws_t::jws_es384
     *          "ES512"             | jws_t::jws_es512
     *          "PS256"             | jws_t::jws_ps256
     *          "PS384"             | jws_t::jws_ps384
     *          "PS512"             | jws_t::jws_ps512
     *          "EdDSA"             | jws_t::jws_eddsa
     *          --------------------+-----------
     */
    return_t typeof_jose_signature(const char* sig, jws_t& type);

    /**
     * @brief nid
     * @param const char* curve [in] P-256, P-384, P521, Ed25519, Ed448, X25519, X448
     * @param uint32& nid [out]
     *    415 : NID_X9_62_prime256v1 (prime256v1)
     *    715 : NID_secp384r1 (secp384r1)
     *    716 : NID_secp521r1 (secp521r1)
     *    1034: NID_X25519
     *    1035: NID_X448
     *    1087: NID_ED25519
     *    1088: NID_ED448
     * @return error code (see error.hpp)
     * @remarks
     *      if following method needed, use nidof_evp_pkey
     *      >> return_t nidof_ec_curve (EVP_PKEY* pkey, uint32& nid);
     */
    return_t nidof_ec_curve(const char* curve, uint32& nid);

    /**
     * @brief kty
     * @param const char* curve [in] P-256, P-384, P521, Ed25519, Ed448, X25519, X448
     * @param uint32& kty [out]
     * @return error code (see error.hpp)
     * @remarks
     *          --------------------------------+----------------
     *          P-256, P-384, P521              | crypto_kty_t::kty_ec
     *          Ed25519, Ed448, X25519, X448    | crypto_kty_t::kty_okp
     *          --------------------------------+----------------
     */
    return_t ktyof_ec_curve(const char* curve, uint32& kty);
    /**
     * @brief kty
     * @param const EVP_PKEY* pkey [in]
     * @param std::string& kty [out]
     *          oct
     *          RSA
     *          EC
     *          OKP
     * @return error code (see error.hpp)
     */
    return_t ktyof_ec_curve(const EVP_PKEY* pkey, std::string& kty);
    /**
     * @brief kty
     * @param const EVP_PKEY* pkey [in]
     * @param crypto_kty_t& kty [out] crypto_kty_t::kty_oct, crypto_kty_t::kty_rsa, crypto_kty_t::kty_ec, crypto_kty_t::kty_okp
     * @return error code (see error.hpp)
     */
    return_t ktyof_ec_curve(const EVP_PKEY* pkey, crypto_kty_t& kty);
    /**
     * @brief "alg" from key
     * @param const EVP_PKEY* pkey [in]
     * @param std::string& curve_name [out]
     *          "P-256", "P384", "P-521", "Ed25519", "Ed448", "X25519", "X448"
     * @return error code (see error.hpp)
     * @example
     *          if (kindof_ecc (pkey)) {
     *              advisor->nameof_ec_curve (pkey, curve_name);
     *          }
     */
    return_t nameof_ec_curve(const EVP_PKEY* pkey, std::string& curve_name);

    /**
     * @brief kind of
     * @param const EVP_PKEY* pkey [in]
     * @param jwa_t alg [in]
     * @return true if match, false if not
     */
    bool is_kindof(const EVP_PKEY* pkey, jwa_t alg);
    /**
     * @brief kind of
     * @param const EVP_PKEY* pkey [in]
     * @param crypt_sig_t sig [in]
     * @return true if match, false if not
     */
    bool is_kindof(const EVP_PKEY* pkey, crypt_sig_t sig);
    /**
     * @brief kind of
     * @param const EVP_PKEY* pkey [in]
     * @param jws_t sig [in]
     * @return true if match, false if not
     */
    bool is_kindof(const EVP_PKEY* pkey, jws_t sig);
    /**
     * @brief kind of
     * @param const EVP_PKEY* pkey [in]
     * @param cose_alg_t alg [in]
     * @return true if match, false if not
     */
    bool is_kindof(const EVP_PKEY* pkey, cose_alg_t alg);
    /**
     * @brief kind of
     * @param const EVP_PKEY* pkey [in]
     * @param const char* alg [in] signature algorithms
     * @return true if match, false if not
     */
    bool is_kindof(const EVP_PKEY* pkey, const char* alg);

    cose_kty_t ktyof(crypto_kty_t kty);
    crypto_kty_t ktyof(cose_kty_t kty);
    jws_t sigof(crypt_sig_t sig);
    crypt_category_t categoryof(cose_alg_t alg);
    crypt_sig_t sigof(cose_alg_t sig);
    crypt_sig_t sigof(jws_t sig);
    cose_ec_curve_t curveof(uint32 nid);
    uint32 curveof(cose_ec_curve_t curve);

    /**
     * query_feature("scrypt")
     *  in openssl-1.1.1 return false
     *  in openssl-3.0.x return true
     * features
     *   cipher
     *     aes-128-cbc, ...
     *     aria-128-cbc, ...
     *     bf-cbc, ...
     *     camellia-128-cbc, ...
     *     cast5-cbc, ...
     *     idea-cbc, ...
     *     rc2-cbc, ...
     *     rc5-cbc, ...
     *     sm4-cbc, ...
     *     seed-cbc, ...
     *     chacha20, chacha20-poly1305, ...
     *   digest
     *     md4, md5,
     *     sha1,
     *     sha224, sha256, sha384, sha512, sha2-512/224, sha2-512/256
     *     sha3-224, sha3-256, sha3-384, sha3-512,
     *     shake128, shake256, blake2b512, blake2s256,
     *     ripemd160, whirlpool
     *   JWA
     *     RSA1_5, RSA-OAEP, RSA-OAEP-256,
     *     A128KW, A192KW, A256KW,
     *     dir,
     *     ECDH-ES,
     *     ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW,
     *     A128GCMKW, A192GCMKW, A256GCMKW,
     *     PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW
     *   JWE
     *     A128CBC-HS256, A192CBC-HS384, A256CBC-HS512
     *     A128GCM, A192GCM, A256GCM
     *   JWS
     *     HS256, HS384, HS512,
     *     RS256, RS384, RS512, RS1
     *     ES256, ES384, ES512, ES256K
     *     PS256, PS384, PS512,
     *     EdDSA
     *   COSE
     *     A128KW, A192KW, A256KW,
     *     direct,
     *     ES256, ES384, ES512, ES256K,
     *     RS256, RS384, RS512, RS1
     *     HS256/256, HS384/384, HS512/512, HS256/64
     *     EdDSA,
     *     direct+HKDF-SHA-256, direct+HKDF-SHA-512,
     *     direct+HKDF-AES-128, direct+HKDF-AES-256,
     *     SHA-1,
     *     SHA-256/64, SHA-256, SHA-512/256, SHA-384, SHA-512, SHAKE128, SHAKE256,
     *     ECDH-ES + HKDF-256, ECDH-ES + HKDF-512,
     *     ECDH-SS + HKDF-256, ECDH-SS + HKDF-512,
     *     ECDH-ES + A128KW, ECDH-ES + A192KW, ECDH-ES + A256KW,
     *     ECDH-SS + A128KW, ECDH-SS + A192KW, ECDH-SS + A256KW,
     *     RSA-PSS-256, RSA-PSS-384, RSA-PSS-512,
     *     RSA-OAEP, RSA-OAEP-256, RSA-OAEP-512,
     *     A128GCM, A192GCM, A256GCM,
     *     AES-CCM-16-64-128, AES-CCM-16-64-256, AES-CCM-64-64-128,
     *     AES-CCM-64-64-256, AES-CCM-16-128-128, AES-CCM-16-128-256,
     *     AES-CCM-64-128-128, AES-CCM-64-128-256, AES-MAC-128/64,
     *     AES-MAC-256/64, AES-MAC-128/128, AES-MAC-256/128,
     *     // ChaCha20/Poly1305, IV-GENERATION
     *   CURVE
     *     P-192, P-224, P-256, P-384, P-521,
     *     K-163, K-233, K-283, K-409, K-571,
     *     B-163, B-233, B-283, B-409, B-571,
     *     Ed25519, Ed448, X25519, X448
     */
    bool query_feature(const char* feature, uint32 spec = 0);
    bool check_minimum_version(unsigned long osslver);

    /**
     * @brief   cookie secret
     * @param   uint8 key [in]
     * @param   size_t secret_size [in]
     * @param   binary_t& secret [out]
     * @example
     *          advisor->get_cookie_secret(0, 16, secret); // generate 16 bytes
     *          advisor->get_cookie_secret(0, 16, secret); // read generated secret, secret_size ignored
     */
    void get_cookie_secret(uint8 key, size_t secret_size, binary_t& secret);

    static void trace(std::function<void(trace_category_t category, uint32 event, stream_t* s)> f);

   protected:
    return_t load();
    return_t build();
    return_t cleanup();

   private:
    crypto_advisor();

    static crypto_advisor _instance;

    /* data structures for a binary search */

    typedef std::map<uint32, const hint_blockcipher_t*> blockcipher_map_t; /* pair (alg, hint_blockcipher_t*) */
    typedef std::map<uint32, EVP_CIPHER*> cipher_map_t;                    /* pair (alg+mode, EVP_CIPHER*) */
    typedef std::map<uint32, const hint_cipher_t*> cipher_fetch_map_t;     /* pair (alg+mode, hint_cipher_t*) */
    typedef std::map<const EVP_CIPHER*, const hint_cipher_t*> evp_cipher_map_t;
    typedef std::map<uint32, EVP_MD*> md_map_t; /* pair (alg+mode, EVP_MD*) */
    typedef std::map<uint32, const hint_digest_t*> md_fetch_map_t;
    typedef std::map<uint32, const hint_jose_encryption_t*> jose_encryption_map_t;
    typedef std::map<uint32, const hint_signature_t*> signature_map_t;
    typedef std::map<uint32, const hint_cose_algorithm_t*> cose_algorithm_map_t;
    typedef std::multimap<uint32, const hint_signature_t*> jose_signature_bynid_map_t;
    typedef std::map<std::string, const hint_jose_encryption_t*> jose_encryption_byname_map_t;
    typedef std::map<std::string, const hint_signature_t*> signature_byname_map_t;
    typedef std::map<std::string, const hint_cose_algorithm_t*> cose_algorithm_byname_map_t;
    typedef std::map<std::string, const hint_curve_t*> jose_nid_bycurve_map_t;
    typedef std::map<uint32, const hint_curve_t*> jose_curve_bynid_map_t;
    typedef std::map<cose_ec_curve_t, const hint_curve_t*> cose_curve_map_t;
    typedef std::map<crypto_kty_t, cose_kty_t> kty2cose_map_t;
    typedef std::map<cose_kty_t, crypto_kty_t> cose2kty_map_t;
    typedef std::map<crypt_sig_t, jws_t> sig2jws_map_t;
    typedef std::map<crypt_sig_t, cose_alg_t> sig2cose_map_t;
    typedef std::map<cose_alg_t, crypt_sig_t> cose2sig_map_t;
    typedef std::map<jws_t, crypt_sig_t> jws2sig_map_t;
    typedef std::map<uint32, cose_ec_curve_t> nid2curve_map_t;
    typedef std::map<cose_ec_curve_t, uint32> curve2nid_map_t;

    typedef std::map<std::string, const hint_cipher_t*> cipher_byname_map_t; /* "aes-256-cbc" to hint_cipher_t* */
    typedef std::map<std::string, const hint_digest_t*> md_byname_map_t;     /* "sha256" to hint_digest_t* */

    int _flag;

    blockcipher_map_t _blockcipher_map;
    cipher_map_t _cipher_map;
    cipher_fetch_map_t _cipher_fetch_map;
    evp_cipher_map_t _evp_cipher_map;
    md_map_t _md_map;
    md_fetch_map_t _md_fetch_map;

    jose_encryption_map_t _alg_map;
    jose_encryption_map_t _enc_map;
    signature_map_t _crypt_sig_map;
    signature_map_t _jose_sig_map;
    cose_algorithm_map_t _cose_alg_map;
    jose_signature_bynid_map_t _sig_bynid_map;

    jose_encryption_byname_map_t _alg_byname_map;
    jose_encryption_byname_map_t _enc_byname_map;
    signature_byname_map_t _sig_byname_map;
    cose_algorithm_byname_map_t _cose_algorithm_byname_map;

    jose_nid_bycurve_map_t _nid_bycurve_map;
    jose_curve_bynid_map_t _curve_bynid_map;
    cose_curve_map_t _cose_curve_map;

    kty2cose_map_t _kty2cose_map;
    cose2kty_map_t _cose2kty_map;
    sig2jws_map_t _sig2jws_map;
    jws2sig_map_t _jws2sig_map;
    sig2cose_map_t _sig2cose_map;
    cose2sig_map_t _cose2sig_map;
    nid2curve_map_t _nid2curve_map;
    curve2nid_map_t _curve2nid_map;

    cipher_byname_map_t _cipher_byname_map;
    md_byname_map_t _md_byname_map;

    std::map<std::string, uint32> _features;
    std::map<std::string, uint32> _versions;

    std::map<uint8, binary_t> _cookie_secret;

    critical_section _lock;
};

extern const hint_cipher_t evp_cipher_methods[];
extern const hint_digest_t evp_md_methods[];
extern const hint_blockcipher_t hint_blockciphers[];
extern const hint_curve_t hint_curves[];
extern const hint_cose_group_t hint_cose_groups[];
extern const hint_cose_algorithm_t hint_cose_algorithms[];
extern const hint_jose_encryption_t hint_jose_algorithms[];
extern const hint_jose_encryption_t hint_jose_encryptions[];
extern const hint_kty_name_t hint_kty_names[];
extern const hint_signature_t hint_signatures[];

extern const size_t sizeof_evp_cipher_methods;
extern const size_t sizeof_evp_md_methods;
extern const size_t sizeof_hint_blockciphers;
extern const size_t sizeof_hint_curves;
extern const size_t sizeof_hint_cose_groups;
extern const size_t sizeof_hint_cose_algorithms;
extern const size_t sizeof_hint_jose_algorithms;
extern const size_t sizeof_hint_jose_encryptions;
extern const size_t sizeof_hint_kty_names;
extern const size_t sizeof_hint_signatures;

}  // namespace crypto
}  // namespace hotplace

#endif
