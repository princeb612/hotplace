/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 7516 JSON Web Encryption (JWE)
 *  RFC 7518 JSON Web Algorithms (JWA)
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_JOSE_ENCRYPTION__
#define __HOTPLACE_SDK_CRYPTO_JOSE_ENCRYPTION__

#include <hotplace/sdk/crypto/jose/types.hpp>

namespace hotplace {
namespace crypto {

class json_object_encryption {
   public:
    json_object_encryption();
    ~json_object_encryption();

    /**
     * @brief encrypt
     * @param jose_context_t* context [in]
     * @param jwe_t enc [in]
     * @param jwa_t alg [in] support all algorithms including jwa_t::jwa_dir, jwa_t::jwa_ecdh_es
     * @param binary_t const& input [in]
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
     *          ret = jose.encrypt (handle_encrypt, jwe_t::jwe_a128cbc_hs256, jwa_t::jwa_ecdh_es, convert (input), encrypted, jose_serialization_t::jose_json);
     *          ret = jose.decrypt (handle_decrypt, encrypted, output, result);
     *          jose.close (handle_encrypt);
     *          jose.close (handle_decrypt);
     */
    return_t encrypt(jose_context_t* context, jwe_t enc, jwa_t alg, binary_t const& input, std::string& output,
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
     * @param binary_t const& input [in]
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
     *          ret = jose.encrypt (handle_encrypt, jwe_t::jwe_a128cbc_hs256, algs, convert (input), encrypted, jose_serialization_t::jose_json);
     *          jose.close (handle_encrypt);
     */
    return_t encrypt(jose_context_t* context, jwe_t enc, std::list<jwa_t> algs, binary_t const& input, std::string& output,
                     jose_serialization_t type = jose_serialization_t::jose_compact);
    /**
     * @brief decrypt
     * @param jose_context_t* context [in]
     * @param std::string const& input [in]
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
     *
     * // example - encrypted
     *  {"protected": "eyJlbmMiOiAiQTEyOENCQy1IUzI1NiJ9",
     *   "recipients": [
     *      {"header": {"alg": "RSA1_5", "kid": "frodo.baggins@hobbiton.example"},
     *       "encrypted_key":
     * "KGbXcQF8eRAlcMeAtCzlFVnPqK3_KOGXpSeAzut-1xUv9-14MNRPr_uewcR-Ffr3s3Ct86Rh_dYrjJPFuNsTmJALqpxiTKiU5JBu5peT2jwqv86JUao-sKtyMmCzyk1p_El_OZgbm8s0FaqsUw4289tRRHZtLJ76egZR8X8_hkXlGXumeLua6pu6XbTPhh3xzim8gzVLXYBkPgPAH_Kg4j2f_HlW3x4KUfG_JNda_1eBaHNmzzPlRsk15pSbyg-llUZ5_YY5whf6F7AZq6a4o2pJMUpkRaYswfxzF0NBIXvNE6jX7nuwMC5HTLJX5hnt9SXhdDcJsqSGqMrYfxP4MA"},
     *      {"header": {"alg": "RSA-OAEP", "kid": "frodo.baggins@hobbiton.example"},
     *       "encrypted_key":
     * "Wsi21h8ic5figyXgI1TYYbxOfMXDsYtq8UVL47NknTN805MGmx_rkO5RWShS6SXv_ipIjUTkQylZw3Z6bdjHuI_V_1bCFVP8ULVrNlVWWUgIuQPgsljx-cQ340zMSV7T7APtIdoFzKeisRHn_wZA6JaFXwqVrwBjTfgDyyO6K_3kPUlbjeM8voS3zHlb5fticIQ-u6btDBbGCUQhAiiqRWLkeANOpoHNtZRZyVoWl1KEq5Lpe2yyFusrx9pP8szm9jY14mmqCyGMdcRxVfUe1MkQxDSvH2GVZyV8BqwiYHzDdaq0KApdh4Z1nDFS3dVy7S7aQiD5jFZw6jlV7PQ4mA"},
     *      {"header": {"alg": "RSA-OAEP-256", "kid": "frodo.baggins@hobbiton.example"},
     *       "encrypted_key":
     * "C-zsNr08_AUjQoPuf-vyvsPEfUQWQ213bzMaIMr42mpYT8i7wsVDy_rWuO9ZTKCbg69d1DgJyoo3X3jfPuL6LZ4MTX8LqgW1k95B-8487aylap4tPe71X9Bcboch-Jyvt8tE02k180oQmc8Zqv4TPBxxi99SLd-naIUYniqXaKzEpToLrOTFWZATuKPKWlp7hotYKTQ78YRGSI8vKKgoDfIeKyS5Vf3KccjY7FNymgio95A7zdajStSo4ABKg_dvheioz07jzk_xBbYCS5E_TT9lj1BY7L1ReVBt51tK_nZAdP7o054oaTO58k_lUQI4gDRC0t48RqAhjcH_4pJ4oQ"},
     *      {"header": {"alg": "A128KW", "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a"},
     *       "encrypted_key": "MLp8i77BOC7dVYa6PolBuS18XEPDMFYQXZ_olplOkPJIX_mesM4mgA"},
     *      {"header": {"alg": "A192KW", "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a"},
     *       "encrypted_key": "7kX_1BNCCTu8gHveetCMP4L91bSZK3ZtcJUPQUbUo46aFUZ0Nb8-_A"},
     *      {"header": {"alg": "A256KW", "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a"},
     *       "encrypted_key": "_iy2IwYaSjUJlNUk9uMZbxfQTj2wPGnlgOUGv2Y8mjToKr1GDWHWcg"},
     *      {"header": {"alg": "ECDH-ES+A128KW", "kid": "peregrin.took@tuckborough.example",
     *       "epk": {"kty": "EC", "crv": "P-384", "x": "DySEu1fz1WB_gxb2u1BbDYrgsWjMGJbBBUduRutOXZ_JS7JROuRptRNUmqRVZRTC", "y":
     * "8IBDL01wpxui3--JymhywkBQbnAxX9PXzl8s2wSEwKfyyEUO9YG00UmGqa66xFc-"}}, "encrypted_key": "B8T6S32j7Q58wbM415kfMJzjMfjKvh9_NXiRx7Vq4EripCazrBs0KQ"},
     *      {"header": {"alg": "ECDH-ES+A192KW", "kid": "peregrin.took@tuckborough.example",
     *       "epk": {"kty": "EC", "crv": "P-384", "x": "HNIDhpVpD9wFFX1s4xEk3NMrmexHfYxAgtIRxvoN5McGjUTU7JpgblLyjPm7Y2xK", "y":
     * "LuaD778coVRIet_su1Qb5CO_2uG2BnoEqsQE-xOEdViiqzsh8of_QTxjyNXdkrRE"}}, "encrypted_key": "dzsCf2mTXM_jMiqBFYMv8wVbiFejUTMWGO8OuDZRZ4X55H4FS2_yGw"},
     *      {"header": {"alg": "ECDH-ES+A256KW", "kid": "peregrin.took@tuckborough.example",
     *       "epk": {"kty": "EC", "crv": "P-384", "x": "npgTumPJvQ6WKpjfjfiGR0gpWTY75nAPfuMLzt7ico1xDLo2yj3Qwce5z_qhzJLr", "y":
     * "DliseK78awHENf_9dcFLnaT1E8RzmamXndmWJTxKZSKJyLhhkV8ewLCNdZXmOrLj"}}, "encrypted_key": "Q9_3U8yXmugTQpy-0eorHqeIC5bVtV8l6CkmIoxQDrtLgkMwi_BNGQ"},
     *      {"header": {"alg": "A128GCMKW", "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a", "iv": "thUHEx9fCR8mrXhL", "tag": "3uUjArEoZi8WhBdaBE2Rhg"},
     *       "encrypted_key": "njLncUjC7X1NpmdRjle6BvAl3ImPaQmk9BiKogzRmGI"},
     *      {"header": {"alg": "A192GCMKW", "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a", "iv": "5TaGEgdIt_1b5R4h", "tag": "ARquxgLT3m1h8qNr84RDBw"},
     *       "encrypted_key": "HwHsimw9jQdV_88-LSN9BHTYBzYQT8lYZXxui90mn6M"},
     *      {"header": {"alg": "A256GCMKW", "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a", "iv": "VV9UjrJSvXIYoXsz", "tag": "jK98qNPv0QLXmtX3FBJzpQ"},
     *       "encrypted_key": "SgFi64wywD9d-skSu2Co5et0llDDkX48NeVXZgsyBxQ"},
     *      {"header": {"alg": "PBES2-HS256+A128KW", "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a", "p2s":
     * "g2WquCyAuF5c4nUdAHpWu9i15jmZ_XKrfKcCvihGnM9UrAZPiHpk1bcUEB6HU6mgk3zsSfqhPNab5GpMxyukKg", "p2c": 15495}, "encrypted_key":
     * "mOs5EE4RxDgElmjVOSRg1fY4ESu1VRRRou-wH7NPNKCLsHaYfZ61Tg"},
     *      {"header": {"alg": "PBES2-HS384+A192KW", "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a", "p2s":
     * "gnoqg6ULsYGonqP3k5aSifYJA-0ZDPGdzSmYVWbzm6gt2M6iF2QoKjBpsMbwp0syA_0nCTTVWWScIcomRvfxZQ", "p2c": 21523}, "encrypted_key":
     * "Q5rQ_qqhqZjGjOq0Nmve4BTBcQdZhsqmd3cWSUBUo9y_TyGUg6FzPg"},
     *      {"header": {"alg": "PBES2-HS512+A256KW", "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a", "p2s":
     * "_7dKhZ4EIT5Rz3rDMtWjmaTpoyg3FfhZloZGKc4_V3_kIMEwCNEAh8liLnYCDCLWM2DSGWo-AbzVDG4LLeo58g", "p2c": 13556}, "encrypted_key":
     * "WuL_vp9EdzJ6JedkHz0ucVAp1XDuj6q2nzxNjvdOpLbc1Zyi0dpQLQ"}
     *   ],
     *   "iv": "uid2drN97IQWj1mpz9CCOA",
     *   "ciphertext": "y6KVk-gfHzYpyzhMjK_0pYffJadptogBjjawa_y_JKCl4QrSFx9qgpSmUVrNLKKCmu16nkxTceV9fYs4tYBuYw",
     *   "tag": "IlSUsTZkN-5ExPfnC1fl7A"
     *  }
     */
    return_t decrypt(jose_context_t* context, std::string const& input, binary_t& output, bool& result);

   protected:
    /**
     * @brief encrypt
     * @param jose_context_t* handle [in] see json_object_signing_encryption::open and close
     * @param jwe_t enc [in]
     * @param jwa_t alg [in]
     * @param binary_t const& input [in]
     * @param binary_t& output [out]
     * @return error code (see error.hpp)
     * @remarks see json_object_signing_encryption::encrypt
     */
    return_t encrypt(jose_context_t* handle, jwe_t enc, jwa_t alg, binary_t const& input, binary_t& output);
    /**
     * @brief decrypt
     * @param jose_context_t* handle
     * @param jwe_t enc [in]
     * @param jwa_t alg [in]
     * @param binary_t const& input [in]
     * @param binary_t& output [out]
     * @return error code (see error.hpp)
     * @remarks see json_object_signing_encryption::decrypt
     */
    return_t decrypt(jose_context_t* handle, jwe_t enc, jwa_t alg, binary_t const& input, binary_t& output);
    /**
     * @brief decrypt
     * @param jose_context_t* handle
     * @param jwe_t enc [in]
     * @param jwa_t alg [in]
     * @param const char* kid [in]
     * @param binary_t const& input [in]
     * @param binary_t& output [out]
     * @return error code (see error.hpp)
     * @remarks see json_object_signing_encryption::decrypt
     */
    return_t decrypt(jose_context_t* handle, jwe_t enc, jwa_t alg, const char* kid, binary_t const& input, binary_t& output);

    /**
     * @brief constraints
     * @param jwa_t alg [in]
     * @param EVP_PKEY* pkey [in]
     */
    return_t check_constraints(jwa_t alg, EVP_PKEY* pkey);
    /**
     * @brief update tag after AESGCMKW
     * @param std::string const& source_encoded [in]
     * @param binary_t const& tag [in]
     * @param binary_t& aad [out]
     * @param std::string& output_encoded [out]
     */
    return_t update_header(std::string const& source_encoded, binary_t const& tag, binary_t& aad, std::string& output_encoded);
    /**
     * @brief encryption
     * @param jwe_t enc [in]
     * @param std::list<jwa_t> const& algs [in]
     * @remarks
     *          compose recipient and header
     *          see also compose_encryption_header, prepare_encryption_recipient
     */
    return_t prepare_encryption(jose_context_t* context, jwe_t enc, std::list<jwa_t> const& algs);
    /**
     * @brief header
     * @param binary_t& header [out]
     * @param jwe_t enc [in]
     * @param jwa_t alg [in]
     * @param jose_compose_t flag [in]
     * @param std::string const& kid [in]
     * @param uint32 flags [inopt] see setoption
     * @remarks
     *      compose_encryption_header (header, jwe_t::jwe_a128cbc_hs256, jwa_t::jwa_unknown, jose_compose_t::jose_enc_alg, "");
     */
    return_t compose_encryption_header(binary_t& header, jwe_t enc, jwa_t alg, jose_compose_t flag, std::string const& kid, uint32 flags = 0);
    /**
     * @brief header
     * @param binary_t& header [out]
     * @param jwe_t enc [in]
     * @param jwa_t alg [in]
     * @param jose_compose_t flag [in]
     * @param std::string const& kid [in]
     * @param crypt_datamap_t& datamap [in]
     * @param crypt_variantmap_t& variantmap [in]
     * @param uint32 flags [inopt] see setoption
     */
    return_t compose_encryption_header(binary_t& header, jwe_t enc, jwa_t alg, jose_compose_t flag, std::string const& kid, crypt_datamap_t& datamap,
                                       crypt_variantmap_t& variantmap, uint32 flags = 0);
    /**
     * @biref recipient
     * @param jwa_t alg [in]
     * @param EVP_PKEY* pkey [in]
     * @param jose_recipient_t& recipient [out]
     * @param crypt_datamap_t& datamap [out]
     * @param crypt_variantmap_t& variantmap [out]
     * @remarks
     *      read from key or generate random value
     *
     *      jwa_group_t::jwa_type_ecdh, jwa_group_t::jwa_type_ecdh_aeskw : epk
     *      jwa_group_t::jwa_type_aesgcmkw : iv, tag
     *      jwa_group_t::jwa_type_pbes_hs_aeskw : p2s, p2c
     */
    return_t prepare_encryption_recipient(jwa_t alg, EVP_PKEY* pkey, jose_recipient_t& recipient, crypt_datamap_t& datamap, crypt_variantmap_t& variantmap);
    /**
     * @brief parse
     * @param jose_context_t* context [in]
     * @param const char* input [in] compact, flattened, serialization
     */
    return_t prepare_decryption(jose_context_t* context, const char* input);

    /**
     * @brief decrypt
     * @param jose_context_t* context [in]
     * @param const char* protected_header [in]
     * @param const char* encrypted_key [in]
     * @param const char* iv [in]
     * @param const char* ciphertext [in]
     * @param const char* tag [in]
     * @param void* json_root [in]
     * @param jwe_t& type [out]
     * @param jose_encryption_t& item [out]
     */
    return_t prepare_decryption(jose_context_t* context, const char* protected_header, const char* encrypted_key, const char* iv, const char* ciphertext,
                                const char* tag, void* json_root, jwe_t& type, jose_encryption_t& item);
    /**
     * @brief decrypt
     * @param jose_context_t* context [in]
     * @param const char* protected_header [in]
     * @param const char* encrypted_key [in]
     * @param void* json_root [in]
     * @param void* json_recipient_header [in]
     * @param jwa_t& type [out]
     * @param jose_recipient_t& recipient [out]
     */
    return_t prepare_decryption_recipient(jose_context_t* context, const char* protected_header, const char* encrypted_key, void* json_root,
                                          void* json_recipient_header, jwa_t& type, jose_recipient_t& recipient);
    /**
     * @brief write
     * @param jose_context_t* context [in]
     * @param std::string& output [out]
     * @param jose_serialization_t type [inopt]
     */
    return_t write_encryption(jose_context_t* context, std::string& output, jose_serialization_t type = jose_serialization_t::jose_compact);
};

}  // namespace crypto
}  // namespace hotplace

#endif
