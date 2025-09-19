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

#ifndef __HOTPLACE_SDK_CRYPTO_COSE_COSEPROTECTED__
#define __HOTPLACE_SDK_CRYPTO_COSE_COSEPROTECTED__

#include <hotplace/sdk/crypto/basic/types.hpp>
#include <hotplace/sdk/crypto/cose/cose_data.hpp>
#include <hotplace/sdk/crypto/cose/types.hpp>
#include <hotplace/sdk/io/cbor/cbor.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief protected
 */
class cose_protected {
    friend class cose_composer;
    friend class cose_data;
    friend class cose_recipient;

   public:
    cose_protected();
    ~cose_protected();

    /**
     * @brief add
     */
    cose_protected& add(cose_key_t key, uint32 value);
    /**
     * @brief set
     */
    cose_protected& set(const binary_t& bin);
    /**
     * @brief data
     */
    cose_data& data();
    /**
     * @brief clear
     */
    cose_protected& clear();
    /**
     * @brief cbor
     */
    cbor_data* cbor();

   protected:
    /**
     * @brief set
     */
    return_t set(cbor_data* object);

   private:
    cose_data _protected;
};

}  // namespace crypto
}  // namespace hotplace

#endif
