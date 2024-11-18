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

#include <sdk/base/basic/binary.hpp>
#include <sdk/io/cbor/cbor_data.hpp>
#include <sdk/io/system/types.hpp>
#include <sdk/io/types.hpp>

namespace hotplace {
namespace io {

#if defined __SIZEOF_INT128__
cbor_bignum_int128::cbor_bignum_int128() { _bn.resize(sizeof(int128)); }

cbor_bignum_int128& cbor_bignum_int128::load(byte_t* data, uint32 len) {
    binary_load(_bn, sizeof(uint128), data, len);
    return *this;
}

int128 cbor_bignum_int128::value() { return ntoh128(*(int128*)&_bn[0]); }
#endif

}  // namespace io
}  // namespace hotplace
