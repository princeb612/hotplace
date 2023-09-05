/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.09.01   Soo Han, Kim        refactor
 */

#include <hotplace/sdk/io/cbor/cbor.hpp>
#include <hotplace/sdk/io/system/types.hpp>

namespace hotplace {
namespace io {

cbor_bignum_int128::cbor_bignum_int128 ()
{
    _bn.resize (sizeof (int128));
}

cbor_bignum_int128& cbor_bignum_int128::load (byte_t* data, uint32 len)
{
    memset (&_bn[0], 0, _bn.size ());
    if (data && (len <= 16)) {
        memcpy (&_bn[0] + (16 - len), data, len);
    }
    return *this;
}

int128 cbor_bignum_int128::value ()
{
    return ntoh128 (*(int128*) &_bn[0]);
}

}
}
