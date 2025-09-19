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

#ifndef __HOTPLACE_SDK_CRYPTO_COSE_COSECOUNTERSIGNS__
#define __HOTPLACE_SDK_CRYPTO_COSE_COSECOUNTERSIGNS__

#include <hotplace/sdk/crypto/basic/types.hpp>
#include <hotplace/sdk/crypto/cose/cose_recipients.hpp>
#include <hotplace/sdk/crypto/cose/types.hpp>
#include <hotplace/sdk/io/cbor/cbor.hpp>

namespace hotplace {
namespace crypto {

class cose_countersigns : public cose_recipients {
   public:
    cose_countersigns();
    virtual ~cose_countersigns();

    virtual cbor_array* cbor();
};

}  // namespace crypto
}  // namespace hotplace

#endif
