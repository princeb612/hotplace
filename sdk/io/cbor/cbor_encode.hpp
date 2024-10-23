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

#ifndef __HOTPLACE_SDK_IO_CBOR_CBORENCODE__
#define __HOTPLACE_SDK_IO_CBOR_CBORENCODE__

#include <deque>
#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>
#include <sdk/io/cbor/cbor.hpp>

namespace hotplace {
namespace io {

/*
 * @brief encode
 * @param
 * @example
 *          cbor_encode cbor;
 *          binary_t bin;
 *          variant_t vt;
 *          // variant_set_int8, variant_set_int16, variant_set_int32, variant_set_int64, variant_set_int128
 *          // variant_set_float, variant_set_double, variant_set_bool, variant_set_str
 *          cbor.encode (bin, vt);
 *          basic_stream out;
 *          std::string hex = bin2hex (bin);
 *
 *          // variant_set_xxx examples
 *          variant_set_int8 (vt, 0);
 *          variant_set_int8 (vt, 1);
 *          variant_set_int8 (vt, 10);
 *          variant_set_int8 (vt, 23);
 *          variant_set_int8 (vt, 24);
 *          variant_set_int8 (vt, 25);
 *          variant_set_int8 (vt, 100);
 *          variant_set_int16 (vt, 1000);
 *          variant_set_int32 (vt, 1000000);
 *          variant_set_int64 (vt, 1000000000000);
 *          variant_set_uint128 (vt, atoi128 ("18446744073709551615"));
 *          variant_set_int128 (vt, atoi128 ("18446744073709551616"));
 *          variant_set_int128 (vt, atoi128 ("-18446744073709551616"));
 *          variant_set_int128 (vt, atoi128 ("-18446744073709551617"));
 *          variant_set_int32 (vt, -1);
 *          variant_set_int32 (vt, -10);
 *          variant_set_int16 (vt, -100);
 *          variant_set_int16 (vt, -1000);
 *          variant_set_float (vt, 0.0);
 *          variant_set_double (vt, 0.0);
 *          variant_set_float (vt, -0.0);
 *          variant_set_double (vt, -0.0);
 *          variant_set_float (vt, 1.0);
 *          variant_set_double (vt, 1.0);
 *          variant_set_float (vt, 1.1);
 *          variant_set_double (vt, 1.1);
 *          variant_set_float (vt, 1.5);
 *          variant_set_double (vt, 1.5);
 *          variant_set_float (vt, 65504.0);
 *          variant_set_double (vt, 65504.0);
 *          variant_set_float (vt, 100000.0);
 *          variant_set_double (vt, 100000.0);
 *          variant_set_float (vt, 3.4028234663852886e+38);
 *          variant_set_double (vt, 1.0e+300);
 *          variant_set_float (vt, 5.960464477539063e-8);
 *          variant_set_float (vt, 0.00006103515625);
 *          variant_set_float (vt, -4.0);
 *          variant_set_float (vt, -4.1);
 *          variant_set_bool (vt, false);
 *          variant_set_bool (vt, true);
 *          variant_set_str (vt, "");
 *          variant_set_str (vt, "a");
 *          variant_set_str (vt, "IETF");
 *          variant_set_str (vt, "\"\\");
 *          variant_set_str (vt, "\u00fc");
 *          variant_set_str (vt, "\u6c34");
 */
class cbor_encode {
   public:
    cbor_encode();

    return_t encode(binary_t& bin, variant_t vt);
    return_t encode(binary_t& bin, bool value);
    return_t encode(binary_t& bin, int8 value);
    return_t encode(binary_t& bin, cbor_major_t major, uint8 value);
    return_t encode(binary_t& bin, int16 value);
    return_t encode(binary_t& bin, cbor_major_t major, uint16 value);
    return_t encode(binary_t& bin, int32 value);
    return_t encode(binary_t& bin, cbor_major_t major, uint32 value);
    return_t encode(binary_t& bin, int64 value);
    return_t encode(binary_t& bin, cbor_major_t major, uint64 value);
#if defined __SIZEOF_INT128__
    return_t encode(binary_t& bin, int128 value);
    return_t encode(binary_t& bin, cbor_major_t major, uint128 value);
#endif
    return_t encode(binary_t& bin, uint8 major);
    return_t encodefp16(binary_t& bin, uint16 value);
    return_t encode(binary_t& bin, float value);
    return_t encode(binary_t& bin, double value);
    return_t encode(binary_t& bin, const byte_t* value, size_t size);
    return_t encode(binary_t& bin, const binary_t& value);
    return_t encode(binary_t& bin, char* value);
    return_t encode(binary_t& bin, char* value, size_t size);
    return_t encode(binary_t& bin, cbor_major_t type, cbor_control_t control, cbor_object* object);
    return_t encode(binary_t& bin, cbor_simple_t type, uint8 value);

    return_t add_tag(binary_t& bin, cbor_object* object);
};

}  // namespace io
}  // namespace hotplace

#endif
