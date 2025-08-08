/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 7049 Concise Binary Object Representation (CBOR)
 *  RFC 8949 Concise Binary Object Representation (CBOR)
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_IO_CBOR_CBORBIGNUM__
#define __HOTPLACE_SDK_IO_CBOR_CBORBIGNUM__

#include <sdk/io/cbor/cbor.hpp>

namespace hotplace {
namespace io {

#if defined __SIZEOF_INT128__
class cbor_bignum_int128 {
   public:
    cbor_bignum_int128();

    cbor_bignum_int128& load(byte_t* data, uint32 len);
    int128 value();

   private:
    binary_t _bn;
};
#endif

}  // namespace io
}  // namespace hotplace

#endif
