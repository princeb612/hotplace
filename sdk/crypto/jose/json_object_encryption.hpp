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

#include <sdk/crypto/jose/types.hpp>

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

   protected:
    /**
     * @brief encrypt
     * @param jose_context_t* handle [in] see json_object_signing_encryption::open and close
     * @param jwe_t enc [in]
     * @param jwa_t alg [in]
     * @param const binary_t& input [in]
     * @param binary_t& output [out]
     * @return error code (see error.hpp)
     * @remarks see json_object_signing_encryption::encrypt
     */
    return_t doencrypt(jose_context_t* handle, jwe_t enc, jwa_t alg, const binary_t& input, binary_t& output);
    /**
     * @brief decrypt
     * @param jose_context_t* handle
     * @param jwe_t enc [in]
     * @param jwa_t alg [in]
     * @param const binary_t& input [in]
     * @param binary_t& output [out]
     * @return error code (see error.hpp)
     * @remarks see json_object_signing_encryption::decrypt
     */
    return_t dodecrypt(jose_context_t* handle, jwe_t enc, jwa_t alg, const binary_t& input, binary_t& output);
    /**
     * @brief decrypt
     * @param jose_context_t* handle
     * @param jwe_t enc [in]
     * @param jwa_t alg [in]
     * @param const char* kid [in]
     * @param const binary_t& input [in]
     * @param binary_t& output [out]
     * @return error code (see error.hpp)
     * @remarks see json_object_signing_encryption::decrypt
     */
    return_t dodecrypt(jose_context_t* handle, jwe_t enc, jwa_t alg, const char* kid, const binary_t& input, binary_t& output);

    /**
     * @brief constraints
     * @param jwa_t alg [in]
     * @param const EVP_PKEY* pkey [in]
     */
    return_t check_constraints(jwa_t alg, const EVP_PKEY* pkey);

    class composer {
       public:
        composer();
        /**
         * @brief write
         * @param jose_context_t* context [in]
         * @param std::string& output [out]
         * @param jose_serialization_t type [inopt]
         */
        return_t compose_encryption(jose_context_t* context, std::string& output, jose_serialization_t type = jose_serialization_t::jose_compact);
        /**
         * @brief update tag after AESGCMKW
         * @param const std::string& source_encoded [in]
         * @param const binary_t& tag [in]
         * @param binary_t& aad [out]
         * @param std::string& output_encoded [out]
         */
        return_t compose_encryption_aead_header(const std::string& source_encoded, const binary_t& tag, binary_t& aad, std::string& output_encoded);
        /**
         * @brief encryption
         * @param jwe_t enc [in]
         * @param std::list<jwa_t> const& algs [in]
         * @remarks
         *          compose recipient and header
         *          see also docompose_protected_header, docompose_encryption_recipient_random
         */
        return_t compose_encryption_dorandom(jose_context_t* context, jwe_t enc, std::list<jwa_t> const& algs);
        /**
         * @brief parse
         * @param jose_context_t* context [in]
         * @param const char* input [in] compact, flattened, serialization
         */
        return_t parse_decryption(jose_context_t* context, const char* input);

       protected:
        /**
         * @brief header
         * @param binary_t& header [out]
         * @param jwe_t enc [in]
         * @param jwa_t alg [in]
         * @param jose_compose_t flag [in]
         * @param const std::string& kid [in]
         * @param uint32 flags [inopt] see setoption
         * @remarks
         *      docompose_protected_header (header, jwe_t::jwe_a128cbc_hs256, jwa_t::jwa_unknown, jose_compose_t::jose_enc_alg, "");
         */
        return_t docompose_protected_header(binary_t& header, jwe_t enc, jwa_t alg, jose_compose_t flag, const std::string& kid, uint32 flags = 0);
        /**
         * @brief header
         * @param binary_t& header [out]
         * @param jwe_t enc [in]
         * @param jwa_t alg [in]
         * @param jose_compose_t flag [in]
         * @param const std::string& kid [in]
         * @param crypt_datamap_t& datamap [in]
         * @param crypt_variantmap_t& variantmap [in]
         * @param uint32 flags [inopt] see setoption
         */
        return_t docompose_encryption_header_parameter(binary_t& header, jwe_t enc, jwa_t alg, jose_compose_t flag, const std::string& kid,
                                                       crypt_datamap_t& datamap, crypt_variantmap_t& variantmap, uint32 flags = 0);
        /**
         * @biref recipient
         * @param jwa_t alg [in]
         * @param const EVP_PKEY* pkey [in]
         * @param jose_recipient_t& recipient [out]
         * @param crypt_datamap_t& datamap [out]
         * @param crypt_variantmap_t& variantmap [out]
         * @remarks
         *      read from key or generate random value
         *
         *      jwa_group_t::jwa_group_ecdh, jwa_group_t::jwa_group_ecdh_aeskw : epk
         *      jwa_group_t::jwa_group_aesgcmkw : iv, tag
         *      jwa_group_t::jwa_group_pbes_hs_aeskw : p2s, p2c
         */
        return_t docompose_encryption_recipient_random(jwa_t alg, const EVP_PKEY* pkey, jose_recipient_t& recipient, crypt_datamap_t& datamap,
                                                       crypt_variantmap_t& variantmap);
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
        return_t doparse_decryption(jose_context_t* context, const char* protected_header, const char* encrypted_key, const char* iv, const char* ciphertext,
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
        return_t doparse_decryption_recipient(jose_context_t* context, const char* protected_header, const char* encrypted_key, void* json_root,
                                              void* json_recipient_header, jwa_t& type, jose_recipient_t& recipient);
    };
};

}  // namespace crypto
}  // namespace hotplace

#endif
