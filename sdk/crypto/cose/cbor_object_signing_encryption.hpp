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

#include <sdk/base.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/cose/cose_composer.hpp>
#include <sdk/crypto/cose/types.hpp>
#include <sdk/crypto/types.hpp>
#include <sdk/io/cbor/cbor_data.hpp>
#include <sdk/io/cbor/cbor_map.hpp>
#include <sdk/io/cbor/cbor_publisher.hpp>
#include <sdk/io/cbor/cbor_reader.hpp>

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
     * @param   binary_t const& bin [in]
     * @return  error code (see error.hpp)
     */
    return_t set(cose_context_t* handle, cose_param_t id, binary_t const& bin);

    /**
     * @brief   encrypt ("Encrypt0")
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   std::list<cose_alg_t>& algs [in]
     * @param   binary_t const& input [in]
     * @param   binary_t& output [out]
     * @return  error code (see error.hpp)
     * @example
     *          encrypt (handle, key, cose_aes128gcm, input, output);
     */
    return_t encrypt(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t>& algs, binary_t const& input, binary_t& output);
    /**
     * @brief   decrypt
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   binary_t const& input [in]
     * @param   bool& result [out]
     * @return  error code (see error.hpp)
     * @remarks see json_object_encryption::decrypt
     */
    return_t decrypt(cose_context_t* handle, crypto_key* key, binary_t const& input, binary_t& output, bool& result);
    /**
     * @brief   sign
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   cose_alg_t method [in]
     * @param   binary_t const& input [in]
     * @param   binary_t& output [out]
     * @return  error code (see error.hpp)
     * @remarks see json_object_signing::sign
     */
    return_t sign(cose_context_t* handle, crypto_key* key, cose_alg_t method, binary_t const& input, binary_t& output);
    /**
     * @brief   sign
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   std::list<cose_alg_t> methods [in]
     * @param   binary_t const& input [in]
     * @param   binary_t& output [out]
     * @return  error code (see error.hpp)
     * @remarks see json_object_signing::sign
     */
    return_t sign(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, binary_t const& input, binary_t& output);
    /**
     * @brief   mac
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   std::list<cose_alg_t> methods [in]
     * @param   binary_t const& input [in]
     * @param   binary_t& output [out]
     * @return  error code (see error.hpp)
     */
    return_t mac(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t> methods, binary_t const& input, binary_t& output);
    /**
     * @brief   verify with kid
     * @param   cose_context_t* handle [in]
     * @param   crypto_key* key [in]
     * @param   binary_t const& input [in]
     * @param   bool& result [out]
     * @return  error code (see error.hpp)
     * @remarks see json_object_signing::verify
     */
    return_t verify(cose_context_t* handle, crypto_key* key, binary_t const& input, bool& result);

    /**
     * @brief process
     * @param cose_context_t* handle [in]
     * @param crypto_key* key [in]
     * @param binary_t const& input [in]
     * @param binary_t& output [out]
     * @return  error code (see error.hpp)
     * @examples
     *          cose_context_t* handle = nullptr;
     *          cose.open(&handle);
     *          cose.process(handle, key, cbor, output); // decrypt, verifysign, verifymac (tagged/untagged)
     *          cose.close(handle);
     */
    return_t process(cose_context_t* handle, crypto_key* key, binary_t const& input, binary_t& output, cose_mode_t mode = cose_mode_t::cose_mode_recv);

   protected:
    return_t subprocess(cose_context_t* handle, crypto_key* key, cose_layer* layer, cose_mode_t mode);
    return_t preprocess(cose_context_t* handle, crypto_key* key, std::list<cose_alg_t>& algs, crypt_category_t category, binary_t const& input);
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
