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

#ifndef __HOTPLACE_SDK_CRYPTO_COSE_COSECOUNTERSIGN__
#define __HOTPLACE_SDK_CRYPTO_COSE_COSECOUNTERSIGN__

#include <sdk/crypto/basic/types.hpp>
#include <sdk/crypto/cose/cose_recipient.hpp>
#include <sdk/crypto/cose/types.hpp>
#include <sdk/io/cbor/cbor.hpp>

namespace hotplace {
namespace crypto {

class cose_countersign : public cose_recipient {
   public:
    cose_countersign();
    virtual ~cose_countersign();

    virtual cbor_array* cbor();

   protected:
};

}  // namespace crypto
}  // namespace hotplace

#endif
