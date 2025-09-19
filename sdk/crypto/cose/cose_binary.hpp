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

#ifndef __HOTPLACE_SDK_CRYPTO_COSE_COSEBINARY__
#define __HOTPLACE_SDK_CRYPTO_COSE_COSEBINARY__

#include <hotplace/sdk/crypto/basic/types.hpp>
#include <hotplace/sdk/crypto/cose/cose_data.hpp>
#include <hotplace/sdk/crypto/cose/types.hpp>
#include <hotplace/sdk/io/cbor/cbor.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief signature, ciphertext, tag
 */
class cose_binary {
    friend class cose_composer;
    friend class cose_data;
    friend class cose_recipient;

   public:
    cose_binary();

    /**
     * @brief set
     */
    cose_binary& set_b16(const char* value);
    cose_binary& set_b16(const std::string& value);
    cose_binary& set(const std::string& value);
    cose_binary& set(const binary_t& value);
    /**
     * @brief data
     */
    cose_data& data();
    /**
     * @brief empty, size
     */
    bool empty();
    size_t size();
    void get(binary_t& bin);
    /**
     * @brief clear
     */
    cose_binary& clear();
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
    cose_data _payload;
};

}  // namespace crypto
}  // namespace hotplace

#endif
