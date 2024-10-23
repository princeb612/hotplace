/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_CRYPTO_COSE_CBOROBJECTSIGNINGENCRYPTION__
#define __HOTPLACE_SDK_CRYPTO_COSE_CBOROBJECTSIGNINGENCRYPTION__

#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>
#include <sdk/crypto/cose/types.hpp>
#include <sdk/crypto/types.hpp>

namespace hotplace {
using namespace io;
namespace crypto {

enum cose_mode_t {
    cose_mode_recv = 0,  // decrypt, verifysign, verifymac
    cose_mode_send = 1,  // encrypt, sign, createmac
};

class cbor_object_signing_encryption {
    friend class cbor_object_encryption;
    friend class cbor_object_signing;

   public:
    cbor_object_signing_encryption();
    ~cbor_object_signing_encryption();

    /**
     * @brief   open
     * @param   cose_context_t** handle [out] call close to free
     * @return  error code (see error.hpp)
     */
    return_t open(cose_context_t** handle);
    /**
     * @brief   close
     * @param   cose_context_t* handle [in]
     * @return  error code (see error.hpp)
     */
    return_t close(cose_context_t* handle);
    /**
     * @brief   set flags
     * @param   cose_context_t* handle [in]
     * @param   uint32 flags [in] see cose_flag_t
     * @return  error code (see error.hpp)
     * @example
     *      cose.set (handle, cose_flag_t::cose_flag_auto_keygen);
     *      cose.set (handle, cose_flag_t::cose_flag_allow_debug | cose_flag_t::cose_flag_auto_keygen);
     */
    return_t set(cose_context_t* handle, uint32 flags, uint32 debug_flags = 0);
    return_t get(cose_context_t* handle, uint32& flags, uint32& debug_flags);
    /**
     * @brief   set
     * @param   cose_context_t* handle [in]
     * @param   cose_param_t id [in] cose_external, cose_public, cose_private
     * @param   const binary_t& bin [in]
     * @return  error code (see error.hpp)
     */
    return_t set(cose_context_t* handle, cose_param_t id, const binary_t& bin);

    /**
     * @brief   encrypt
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   std::list<cose_alg_t>& algs [in]
     * @param   const binary_t& input [in]
     * @param   binary_t& output [out] CBOR
     * @return  error code (see error.hpp)
     * @example
     *          const cose_alg_t enc_algs[] = {
     *              cose_aes128gcm,        cose_aes192gcm,         cose_aes256gcm,         cose_aesccm_16_64_128,  cose_aesccm_16_64_256, cose_aesccm_64_64_128,
     *              cose_aesccm_64_64_256, cose_aesccm_16_128_128, cose_aesccm_16_128_256, cose_aesccm_64_128_128, cose_aesccm_64_128_256,
     *          };
     *          const cose_alg_t key_algs[] = {
     *              cose_aes128kw, cose_aes192kw, cose_aes256kw,
     *              cose_direct,
     *              cose_hkdf_sha256, cose_hkdf_sha512,
     *              cose_hkdf_aes128, cose_hkdf_aes256, cose_ecdhes_hkdf_256,
     *              cose_ecdhes_hkdf_512, cose_ecdhss_hkdf_256, cose_ecdhss_hkdf_512,
     *              cose_ecdhes_a128kw, cose_ecdhes_a192kw, cose_ecdhes_a256kw,
     *              cose_ecdhss_a128kw, cose_ecdhss_a192kw, cose_ecdhss_a256kw,
     *              cose_rsaoaep1, cose_rsaoaep256, cose_rsaoaep512,
     *          };
     *          for (i = 0; i < RTL_NUMBER_OF(enc_algs); i++) {
     *              cose_alg_t alg = enc_algs[i];
     *
     *              for (j = 0; j < RTL_NUMBER_OF(key_algs); j++) {
     *                  algs.clear();
     *                  cose_alg_t keyalg = key_algs[j];
     *                  algs.push_back(alg);
     *                  algs.push_back(keyalg);
     *
     *                  cose.encrypt (handle, key, algs, input, output);
     *              }
     *          }
     */
    return_t encrypt(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t>& algs, const binary_t& input, binary_t& output);
    /**
     * @brief   encrypt
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   const binary_t& input [in]
     * @param   binary_t& output [out] CBOR
     * @return  error code (see error.hpp)
     * @example
     *          cose.open(&handle);
     *          // sketch
     *          cose_layer& body = handle->composer->get_layer();
     *          body.get_protected().add(cose_key_t::cose_alg, alg);
     *          if (cose_alg_t::cose_unknown != keyalg) {
     *              cose_recipient& recipient = body.get_recipients().add(new cose_recipient);
     *              recipient.get_protected().add(cose_key_t::cose_alg, keyalg);
     *
     *              // fill others and compose
     *              ret = cose.encrypt(handle, key, input, cbor);
     *          }
     *          cose.close(handle);
     */
    return_t encrypt(cose_context_t* handle, crypto_key* key, const binary_t& input, binary_t& output);
    /**
     * @brief   decrypt
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   const binary_t& input [in]
     * @param   binary_t& output [out] decrypted
     * @param   bool& result [out]
     * @return  error code (see error.hpp)
     * @remarks see json_object_encryption::decrypt
     */
    return_t decrypt(cose_context_t* handle, crypto_key* key, const binary_t& input, binary_t& output, bool& result);
    /**
     * @brief   sign
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   cose_alg_t method [in]
     * @param   const binary_t& input [in]
     * @param   binary_t& output [out] CBOR
     * @return  error code (see error.hpp)
     * @remarks see json_object_signing::sign
     */
    return_t sign(cose_context_t* handle, crypto_key* key, cose_alg_t method, const binary_t& input, binary_t& output);
    /**
     * @brief   sign
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   std::list<cose_alg_t>& methods [in]
     * @param   const binary_t& input [in]
     * @param   binary_t& output [out] CBOR
     * @return  error code (see error.hpp)
     * @remarks see json_object_signing::sign
     * @example
     *          const cose_alg_t sign_algs[] = {
     *              cose_es256, cose_es384, cose_es512, cose_eddsa, cose_ps256, cose_ps384, cose_ps512, cose_es256k, cose_rs256, cose_rs384, cose_rs512,
     * cose_rs1,
     *          };
     *          for (i = 0; i < RTL_NUMBER_OF(sign_algs); i++) {
     *              cose_alg_t alg = sign_algs[i];
     *
     *              algs.clear();
     *              algs.push_back(alg);
     *
     *              cose.sign (handle, key, algs, input, output);
     *          }
     */
    return_t sign(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t>& methods, const binary_t& input, binary_t& output);
    /**
     * @brief   sign
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   const binary_t& input [in]
     * @param   binary_t& output [out] CBOR
     * @return  error code (see error.hpp)
     * @example
     *          cose.open(&handle);
     *          // sketch
     *          cose_layer& body = handle->composer->get_layer();
     *          body.get_protected().add(cose_key_t::cose_alg, alg);
     *
     *          // fill others and compose
     *          ret = cose.sign(handle, key, input, cbor);
     *
     *          cose.close(handle);
     */
    return_t sign(cose_context_t* handle, crypto_key* key, const binary_t& input, binary_t& output);
    /**
     * @brief   mac
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   std::list<cose_alg_t>& methods [in]
     * @param   const binary_t& input [in]
     * @param   binary_t& output [out] CBOR
     * @return  error code (see error.hpp)
     * @example
     *          const cose_alg_t mac_algs[] = {
     *              cose_hs256_64, cose_hs256, cose_hs384, cose_hs512, cose_aesmac_128_64, cose_aesmac_256_64, cose_aesmac_128_128, cose_aesmac_256_128,
     *          };
     *          const cose_alg_t key_algs[] = {
     *              cose_aes128kw, cose_aes192kw, cose_aes256kw,
     *              cose_direct,
     *              cose_hkdf_sha256, cose_hkdf_sha512,
     *              cose_hkdf_aes128, cose_hkdf_aes256, cose_ecdhes_hkdf_256,
     *              cose_ecdhes_hkdf_512, cose_ecdhss_hkdf_256, cose_ecdhss_hkdf_512,
     *              cose_ecdhes_a128kw, cose_ecdhes_a192kw, cose_ecdhes_a256kw,
     *              cose_ecdhss_a128kw, cose_ecdhss_a192kw, cose_ecdhss_a256kw,
     *              cose_rsaoaep1, cose_rsaoaep256, cose_rsaoaep512,
     *          };
     *          for (i = 0; i < RTL_NUMBER_OF(mac_algs); i++) {
     *              cose_alg_t alg = mac_algs[i];
     *
     *              for (j = 0; j < RTL_NUMBER_OF(key_algs); j++) {
     *                  algs.clear();
     *                  cose_alg_t keyalg = key_algs[j];
     *                  algs.push_back(alg);
     *                  algs.push_back(keyalg);
     *
     *                  cose.mac (handle, key, algs, input, output);
     *              }
     *          }
     */

    return_t mac(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t>& methods, const binary_t& input, binary_t& output);
    /**
     * @brief   mac
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   const binary_t& input [in]
     * @param   binary_t& output [out] CBOR
     * @return  error code (see error.hpp)
     * @example
     *          cose.open(&handle);
     *          // sketch
     *          cose_layer& body = handle->composer->get_layer();
     *          body.get_protected().add(cose_key_t::cose_alg, alg);
     *          if (cose_alg_t::cose_unknown != keyalg) {
     *              cose_recipient& recipient = body.get_recipients().add(new cose_recipient);
     *              recipient.get_protected().add(cose_key_t::cose_alg, keyalg);
     *
     *              // fill others and compose
     *              ret = cose.mac(handle, key, input, cbor);
     *          }
     *          cose.close(handle);
     */
    return_t mac(cose_context_t* handle, crypto_key* key, const binary_t& input, binary_t& output);
    /**
     * @brief   verify with kid
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   const binary_t& input [in]
     * @param   bool& result [out]
     * @return  error code (see error.hpp)
     * @remarks see json_object_signing::verify
     */
    return_t verify(cose_context_t* handle, crypto_key* key, const binary_t& input, bool& result);

    /**
     * @brief process
     * @param cose_context_t* handle [in]
     * @param crypto_key* key [in]
     * @param const binary_t& input [in]
     * @param binary_t& output [out]
     * @return  error code (see error.hpp)
     * @examples
     *          cose_context_t* handle = nullptr;
     *          cose.open(&handle);
     *          cose.process(handle, key, cbor, output); // decrypt, verifysign, verifymac (tagged/untagged)
     *          cose.close(handle);
     */
    return_t process(cose_context_t* handle, crypto_key* key, const binary_t& input, binary_t& output, cose_mode_t mode = cose_mode_t::cose_mode_recv);

   protected:
    return_t subprocess(cose_context_t* handle, crypto_key* key, cose_layer* layer, cose_mode_t mode);
    return_t preprocess(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t>& algs, crypt_category_t category, const binary_t& input);
    return_t preprocess(cose_context_t* handle, crypto_key* key, const binary_t& input);

    return_t preprocess_skeleton(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t>& algs, crypt_category_t category, const binary_t& input);
    return_t preprocess_random(cose_context_t* handle, crypto_key* key);
    return_t preprocess_dorandom(cose_context_t* handle, crypto_key* key, cose_layer* layer);

    return_t compose_kdf_context(cose_context_t* handle, cose_layer* layer, binary_t& kdf_context);
    cbor_data* compose_kdf_context_item(cose_context_t* handle, cose_layer* layer, cose_key_t key, cose_param_t param);
    return_t compose_enc_context(cose_context_t* handle, cose_layer* layer, binary_t& aad);
    return_t compose_sign_context(cose_context_t* handle, cose_layer* layer, binary_t& tobesigned);
    return_t compose_mac_context(cose_context_t* handle, cose_layer* layer, binary_t& tomac);

    return_t preprocess_keyagreement(cose_context_t* handle, crypto_key* key, cose_layer* layer);
    return_t process_keyagreement(cose_context_t* handle, crypto_key* key, cose_layer* layer, cose_mode_t mode);

    return_t docrypt(cose_context_t* handle, crypto_key* key, cose_layer* layer, cose_mode_t mode);
    return_t dosign(cose_context_t* handle, crypto_key* key, cose_layer* layer, cose_mode_t mode);
    return_t domac(cose_context_t* handle, crypto_key* key, cose_layer* layer, cose_mode_t mode);

   private:
    typedef return_t (cbor_object_signing_encryption::*subprocess_handler)(cose_context_t* handle, crypto_key* key, cose_layer* layer, cose_mode_t mode);
    std::map<cbor_tag_t, subprocess_handler> _handlermap;
    bool _builtmap;
};

typedef cbor_object_signing_encryption COSE;

}  // namespace crypto
}  // namespace hotplace

#endif
