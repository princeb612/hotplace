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

#ifndef __HOTPLACE_SDK_CRYPTO_COSE_COSEUNPROTECTED__
#define __HOTPLACE_SDK_CRYPTO_COSE_COSEUNPROTECTED__

#include <sdk/crypto/basic/types.hpp>
#include <sdk/crypto/cose/cose_data.hpp>
#include <sdk/crypto/cose/types.hpp>
#include <sdk/io/cbor/cbor.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief unprotected
 */
class cose_unprotected {
    friend class cose_composer;
    friend class cose_data;
    friend class cose_recipient;

   public:
    cose_unprotected();
    ~cose_unprotected();

    /**
     * @brief add
     */
    cose_unprotected& add(cose_key_t key, int32 value);
    cose_unprotected& add(cose_key_t key, const char* value);
    cose_unprotected& add(cose_key_t key, std::string& value);
    cose_unprotected& add(cose_key_t key, const std::string& value);
    cose_unprotected& add(cose_key_t key, binary_t& value);
    cose_unprotected& add(cose_key_t key, const binary_t& value);
    /**
     * @brief ephemeral key
     * @param cose_key_t key [in] cose_key_t::cose_ephemeral_key
     * @param uint16 curve [in]
     * @param const binary_t& x [in]
     * @param const binary_t& y [in]
     */
    cose_unprotected& add(cose_key_t key, uint16 curve, const binary_t& x, const binary_t& y);
    cose_unprotected& add(cose_key_t key, uint16 curve, const binary_t& x, bool ysign);
    /**
     * @brief counter signature
     */
    cose_unprotected& add(cose_alg_t alg, const char* kid, const binary_t& signature);
    /**
     * @brief data
     */
    cose_data& data();
    /**
     * @brief clear
     */
    cose_unprotected& clear();
    /**
     * @brief cbor
     */
    cbor_map* cbor();

   protected:
    /**
     * @brief set
     */
    return_t set(cbor_map* object);

   private:
    cose_data _unprotected;
};

}  // namespace crypto
}  // namespace hotplace

#endif
