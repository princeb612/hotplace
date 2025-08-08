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

#ifndef __HOTPLACE_SDK_CRYPTO_COSE_COSEUNSENT__
#define __HOTPLACE_SDK_CRYPTO_COSE_COSEUNSENT__

#include <sdk/crypto/basic/types.hpp>
#include <sdk/crypto/cose/types.hpp>
#include <sdk/io/cbor/cbor.hpp>

namespace hotplace {
namespace crypto {

class cose_unsent {
    friend class cose_recipient;

   public:
    cose_unsent();
    ~cose_unsent();

    cose_unsent& add(int key, const char* value);
    cose_unsent& add(int key, const unsigned char* value, size_t size);
    cose_unsent& add(int key, binary_t& value);
    cose_unsent& add(int key, const binary_t& value);

    cose_data& data();

   protected:
    bool isvalid(int key);

   private:
    cose_data _unsent;
};

}  // namespace crypto
}  // namespace hotplace

#endif
