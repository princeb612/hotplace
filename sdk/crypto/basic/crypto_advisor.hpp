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

#include <hotplace/sdk/crypto/basic/types.hpp>
#include <algorithm>
#include <functional>
#include <map>

namespace hotplace {
namespace crypto {

class crypto_advisor
{
public:
    static crypto_advisor* get_instance ();

    ~crypto_advisor ();

    /**
     * @brief find blockcipher hint
     * @param int alg [in] crypt_algorithm_t
     * @return hint_blockcipher_t*
     * @remarks EVP_CIPHER_CTX_block_size works wrong ?
     * @example
     *      crypto_advisor* advisor = crypto_advisor::get_instance ();
     *      const hint_blockcipher_t* blockcipher = advisor->hintof_blockcipher (crypt_algorithm_t::aes256);
     *      size_t blocksize = blockcipher->_blocksize;
     */
    const hint_blockcipher_t* hintof_blockcipher (crypt_algorithm_t alg);
    /**
     * @brief find blockcipher hint
     * @param const EVP_CIPHER* cipher [in]
     */
    const hint_blockcipher_t* find_evp_cipher (const EVP_CIPHER* cipher);
    /**
     * @brief find cipher method
     * @param crypt_algorithm_t algorithm [in] crypt_algorithm_t
     * @param crypt_mode_t mode [in] crypt_mode_t
     * @return EVP_CIPHER*
     * @remarks
     *          const EVP_CIPHER* aes_128_cbc = (const EVP_CIPHER*) find_evp_cipher (crypt_algorithm_t::aes128, crypt_mode_t::cbc); // EVP_aes_128_cbc ()
     *
     *          can be nullptr
     *          for example, seed deprecated since openssl 3.0
     */
    const EVP_CIPHER* find_evp_cipher (crypt_algorithm_t algorithm, crypt_mode_t mode);
    /**
     * @brief find alg and mode
     * @param const EVP_CIPHER* cipher [in]
     * @param int& algorithm [out]
     * @param int& mode [out]
     */
    return_t find_evp_cipher (const EVP_CIPHER* cipher, crypt_algorithm_t& algorithm, crypt_mode_t& mode);
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
    const char* nameof_cipher (crypt_algorithm_t algorithm, crypt_mode_t mode);
    /**
     * @brief find md method
     * @param hash_algorithm_t algorithm [in] hash_algorithm_t
     * @return EVP_MD*
     * @remarks
     *          const EVP_MD* sha3_512 = (const EVP_MD*) find_evp_md (hash_algorithm_t::sha3_512); // EVP_sha3_512 ()
     */
    const EVP_MD* find_evp_md (hash_algorithm_t algorithm);
    const EVP_MD* find_evp_md (jws_t sig);
    hash_algorithm_t get_algorithm (jws_t sig);
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
    const char* nameof_md (hash_algorithm_t algorithm);

#if __cplusplus >= 201103L     // c++11
    /**
     * @brief   iteration helper methods  - algoritm encrypton signature
     * @example
     *          crypto_advisor* advisor = crypto_advisor::get_instance ();
     *
     *          std::function <void (const hint_jose_encryption_t*, void*)> lambda1 =
     *                  [] (const hint_jose_encryption_t* item, void* user) -> void { printf ("    %s\n", item->alg_name); };
     *          std::function <void (const hint_jose_signature_t*, void*)> lambda2 =
     *                  [] (const hint_jose_signature_t* item, void* user) -> void { printf ("    %s\n", item->alg_name); };
     *
     *          advisor->jose_for_each_algorithm (lambda1, nullptr );
     *          advisor->jose_for_each_encryption (lambda1, nullptr );
     *
     *          advisor->jose_for_each_signature (lambda2, nullptr );
     */
    return_t jose_for_each_algorithm (std::function <void (const hint_jose_encryption_t*, void*)> f, void* user);
    return_t jose_for_each_encryption (std::function <void (const hint_jose_encryption_t*, void*)> f, void* user);
    return_t jose_for_each_signature (std::function <void (const hint_jose_signature_t*, void*)> f, void* user);
#endif

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
    const hint_jose_encryption_t* hintof_jose_algorithm (jwa_t alg);
    /**
     * @brief hint
     * @param jwe_t enc [in]
     *          jwe_t::jwe_a128cbc_hs256 series, jwe_t::jwe_a128gcm series
     * @return const hint_jose_encryption_t*
     * @example
     *          const hint_jose_encryption_t* enc_info = advisor->hintof_jose_encryption (enc);
     */
    const hint_jose_encryption_t* hintof_jose_encryption (jwe_t enc);
    /**
     * @brief hint
     * @param jws_t sig [in]
     *          jws_t::jws_hs256 series, jws_t::jws_rs256 series, jws_t::jws_es256 series, jws_t::jws_ps256 series, jws_t::jws_eddsa
     * @return const hint_jose_signature_t*
     */
    const hint_jose_signature_t* hintof_jose_signature (jws_t sig);
    /**
     * @brief hint
     * @param uint32 nid [in]
     *          NID_X9_62_prime256v1, NID_secp384r1, NID_secp521r1, NID_ED25519, NID_ED448, NID_X25519, NID_X448
     * @return const hint_curve_t*
     * @sa hintof_curve
     */
    const hint_curve_t* hintof_curve_nid (uint32 nid);

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
    const hint_jose_encryption_t* hintof_jose_algorithm (const char* alg);
    /**
     * @brief hint
     * @param const char* enc [in]
     *          "A128CBC-HS256" series, "A128GCM" series
     * @return const hint_jose_encryption_t*
     */
    const hint_jose_encryption_t* hintof_jose_encryption (const char* enc);
    /**
     * @brief hint
     * @param const char* sig [in]
     *          "HS256" series, "RS256" series, "ES256" series, "PS256" series, "EdDSA"
     * @return const hint_jose_signature_t*
     */
    const hint_jose_signature_t* hintof_jose_signature (const char* sig);
    /**
     * @brief hint
     * @param const char* curve [in]
     *          "P-256" series, "Ed25519", "Ed448", "X25519", "X448"
     * @return const hint_curve_t*
     * @sa hintof_curve_nid
     */
    const hint_curve_t* hintof_curve (const char* curve);

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
    const char* nameof_jose_algorithm (jwa_t alg);
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
    const char* nameof_jose_encryption (jwe_t enc);
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
    const char* nameof_jose_signature (jws_t sig);

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
    return_t typeof_jose_algorithm (const char* alg, jwa_t& type);
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
    return_t typeof_jose_encryption (const char* enc, jwe_t& type);
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
    return_t typeof_jose_signature (const char* sig, jws_t& type);

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
    return_t nidof_ec_curve (const char* curve, uint32& nid);

    /**
     * @brief kty
     * @param const char* curve [in] P-256, P-384, P521, Ed25519, Ed448, X25519, X448
     * @param uint32& kty [out]
     * @return error code (see error.hpp)
     * @remarks
     *          --------------------------------+----------------
     *          P-256, P-384, P521              | crypto_key_t::ec_key
     *          Ed25519, Ed448, X25519, X448    | crypto_key_t::okp_key
     *          --------------------------------+----------------
     */
    return_t ktyof_ec_curve (const char* curve, uint32& kty);
    /**
     * @brief kty
     * @param EVP_PKEY* pkey [in]
     * @param std::string& kty [out]
     *          oct
     *          RSA
     *          EC
     *          OKP
     * @return error code (see error.hpp)
     */
    return_t ktyof_ec_curve (EVP_PKEY* pkey, std::string& kty);
    /**
     * @brief kty
     * @param EVP_PKEY* pkey [in]
     * @param crypto_key_t& kty [out] crypto_key_t::hmac_key, crypto_key_t::rsa_key, crypto_key_t::ec_key, crypto_key_t::okp_key
     * @return error code (see error.hpp)
     */
    return_t ktyof_ec_curve (EVP_PKEY* pkey, crypto_key_t& kty);
    /**
     * @brief "alg" from key
     * @param EVP_PKEY* pkey [in]
     * @param std::string& curve_name [out]
     *          "P-256", "P384", "P-521", "Ed25519", "Ed448", "X25519", "X448"
     * @return error code (see error.hpp)
     * @example
     *          if (kindof_ecc (pkey)) {
     *              advisor->nameof_ec_curve (pkey, curve_name);
     *          }
     */
    return_t nameof_ec_curve (EVP_PKEY* pkey, std::string& curve_name);

    /**
     * @brief kind of
     * @param EVP_PKEY* pkey [in]
     * @param jwa_t alg [in]
     * @return true if match, false if not
     */
    bool is_kindof (EVP_PKEY* pkey, jwa_t alg);
    /**
     * @brief kind of
     * @param EVP_PKEY* pkey [in]
     * @param jws_t sig [in]
     * @return true if match, false if not
     */
    bool is_kindof (EVP_PKEY* pkey, jws_t sig);
    /**
     * @brief kind of
     * @param EVP_PKEY* pkey [in]
     * @param const char* alg [in] signature algorithms
     * @return true if match, false if not
     */
    bool is_kindof (EVP_PKEY* pkey, const char* alg);

protected:
    return_t build_if_necessary ();
    return_t cleanup ();

private:
    crypto_advisor ();

    static crypto_advisor _instance;

    /* data structures for a binary search */

    typedef std::map <uint32, const hint_blockcipher_t*> blockcipher_map_t;             /* pair (alg, hint_blockcipher_t*) */
    typedef std::map <uint32, EVP_CIPHER*> cipher_map_t;                          /* pair (alg+mode, EVP_CIPHER*) */
    typedef std::map <uint32, const openssl_evp_cipher_method_t*> cipher_fetch_map_t;   /* pair (alg+mode, openssl_evp_cipher_method_t*) */
    typedef std::map <const EVP_CIPHER*, const openssl_evp_cipher_method_t*> evp_cipher_map_t;
    typedef std::map <uint32, EVP_MD*> md_map_t;                                  /* pair (alg+mode, EVP_MD*) */
    typedef std::map <uint32, const openssl_evp_md_method_t*> md_fetch_map_t;
    typedef std::map <uint32, const hint_jose_encryption_t*> jose_encryption_map_t;
    typedef std::map <uint32, const hint_jose_signature_t*> jose_signature_map_t;
    typedef std::multimap <uint32, const hint_jose_signature_t*> jose_signature_bynid_map_t;
    typedef std::map <std::string, const hint_jose_encryption_t*> jose_encryption_byname_map_t;
    typedef std::map <std::string, const hint_jose_signature_t*> jose_signature_byname_map_t;
    typedef std::map <std::string, const hint_curve_t*> jose_nid_bycurve_map_t;
    typedef std::map <uint32, const hint_curve_t*> jose_curve_bynid_map_t;

    critical_section _lock;
    int _flag;

    blockcipher_map_t _blockcipher_map;
    cipher_map_t _cipher_map;
    cipher_fetch_map_t _cipher_fetch_map;
    evp_cipher_map_t _evp_cipher_map;
    md_map_t _md_map;
    md_fetch_map_t _md_fetch_map;

    jose_encryption_map_t _alg_map;
    jose_encryption_map_t _enc_map;
    jose_signature_map_t _sig_map;
    jose_signature_bynid_map_t _sig_bynid_map;

    jose_encryption_byname_map_t _alg_byname_map;
    jose_encryption_byname_map_t _enc_byname_map;
    jose_signature_byname_map_t _sig_byname_map;

    jose_nid_bycurve_map_t _nid_bycurve_map;
    jose_curve_bynid_map_t _curve_bynid_map;
};

/**
 * @brief curve
 * @param EVP_PKEY* key [in]
 * @param uint32& nid [out]
 *    415 : NID_X9_62_prime256v1 (prime256v1)
 *    715 : NID_secp384r1 (secp384r1)
 *    716 : NID_secp521r1 (secp521r1)
 *    1087: NID_ED25519
 *    1088: NID_ED448
 * @remarks
 *    opensource native type
 *
 *    # define EVP_PKEY_HMAC     NID_hmac
 *    # define EVP_PKEY_RSA      NID_rsaEncryption
 *    # define EVP_PKEY_EC       NID_X9_62_id_ecPublicKey
 *    # define EVP_PKEY_X25519   NID_X25519
 *    # define EVP_PKEY_X448     NID_X448
 *    # define EVP_PKEY_ED25519  NID_ED25519
 *    # define EVP_PKEY_ED448    NID_ED448
 *
 *    #define NID_hmac                   855
 *    #define NID_rsaEncryption          6
 *    #define NID_X9_62_id_ecPublicKey   408
 *    #define NID_X25519                 1034
 *    #define NID_X448                   1035
 *    #define NID_ED25519                1087
 *    #define NID_ED448                  1088
 *
 *    #define NID_X9_62_prime256v1       415
 *    #define NID_secp384r1              715
 *    #define NID_secp521r1              716
 */
return_t nidof_evp_pkey (EVP_PKEY* key, uint32& nid);
/**
 * @brief kindof
 * @param EVP_PKEY* pkey [in]
 */
bool kindof_ecc (EVP_PKEY* pkey);

/**
 * @param EVP_PKEY* key [in]
 */
crypto_key_t typeof_crypto_key (EVP_PKEY* key);

}
}  // namespace

#endif
