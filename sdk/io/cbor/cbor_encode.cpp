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

#include <hotplace/sdk/base/variant.hpp>
#include <hotplace/sdk/base/basic/ieee754.hpp>
#include <hotplace/sdk/io/cbor/cbor.hpp>
#include <hotplace/sdk/io/system/types.hpp>

namespace hotplace {
namespace io {

cbor_encode::cbor_encode ()
{
    // do nothing
}

return_t cbor_encode::encode (binary_t& bin, variant_t vt)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        switch (vt.type) {
            case TYPE_BOOL:
                encode (bin, vt.data.b);
                break;
            case TYPE_INT8:
                encode (bin, vt.data.i8);
                break;
            case TYPE_UINT8:
                encode (bin, cbor_major_t::cbor_major_uint, vt.data.ui8);
                break;
            case TYPE_INT16:
                encode (bin, vt.data.i16);
                break;
            case TYPE_UINT16:
                encode (bin, cbor_major_t::cbor_major_uint, vt.data.ui16);
                break;
            case TYPE_INT32:
                encode (bin, vt.data.i32);
                break;
            case TYPE_UINT32:
                encode (bin, cbor_major_t::cbor_major_uint, vt.data.ui32);
                break;
            case TYPE_INT64:
                encode (bin, vt.data.i64);
                break;
            case TYPE_UINT64:
                encode (bin, cbor_major_t::cbor_major_uint, vt.data.ui64);
                break;
#if defined __SIZEOF_INT128__
            case TYPE_INT128:
                encode (bin, vt.data.i128);
                break;
            case TYPE_UINT128:
                encode (bin, cbor_major_t::cbor_major_uint, vt.data.ui128);
                break;
#endif
            case TYPE_FP16:
                encodefp16 (bin, vt.data.ui16);
                break;
            case TYPE_FLOAT:
                encode (bin, vt.data.f);
                break;
            case TYPE_DOUBLE:
                encode (bin, vt.data.d);
                break;
            case TYPE_NULL:
            case TYPE_STRING:
                encode (bin, vt.data.str);
                break;
            case TYPE_NSTRING:
                encode (bin, vt.data.str, vt.size);
                break;
            case TYPE_BINARY:
                encode (bin, vt.data.bstr, vt.size);
                break;
            default:
                break;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_encode::encode (binary_t& bin, bool value)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        uint8 major = cbor_major_t::cbor_major_simple;
        uint8 simple = 0;
        if (value) {
            simple = 21;
        } else {
            simple = 20;
        }

        bin.push_back ((major << 5) | simple);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_encode::encode (binary_t& bin, int8 value)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        uint8 major = 0;
        if (value >= 0) {
            major = cbor_major_t::cbor_major_uint;
        } else {
            major = cbor_major_t::cbor_major_nint;
            value += 1;
            value = -value;
        }
        if (value < 24) {
            bin.push_back ((major << 5) | value);
        } else {
            bin.push_back ((major << 5) | 24);
            bin.push_back (value);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_encode::encode (binary_t& bin, cbor_major_t major, uint8 value)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (value < 24) {
            bin.push_back ((major << 5) | value);
        } else {
            bin.push_back ((major << 5) | 24);
            bin.push_back (value);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_encode::encode (binary_t& bin, int16 value)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        uint8 major = 0;
        if (value >= 0) {
            major = cbor_major_t::cbor_major_uint;
        } else {
            major = cbor_major_t::cbor_major_nint;
            value += 1;
            value = -value;
        }
        if (value < 24) {
            bin.push_back ((major << 5) | value);
        } else if (value < 0x100) {
            bin.push_back ((major << 5) | 24);
            bin.push_back (value);
        } else {
            bin.push_back ((major << 5) | 25);
            uint16 be = htons (value);
            bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 2);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_encode::encode (binary_t& bin, cbor_major_t major, uint16 value)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (value < 24) {
            bin.push_back ((major << 5) | value);
        } else if (value < 0x100) {
            bin.push_back ((major << 5) | 24);
            bin.push_back (value);
        } else {
            bin.push_back ((major << 5) | 25);
            uint16 be = htons (value);
            bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 2);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_encode::encode (binary_t& bin, int32 value)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        uint8 major = 0;
        if (value >= 0) {
            major = cbor_major_t::cbor_major_uint;
        } else {
            major = cbor_major_t::cbor_major_nint;
            value += 1;
            value = -value;
        }

        if (value < 24) {
            bin.push_back ((major << 5) | value);
        } else if (value < 0x100) {
            bin.push_back ((major << 5) | 24);
            bin.push_back (value);
        } else if (value < 0x10000) {
            bin.push_back ((major << 5) | 25);
            uint16 be = htons (value);
            bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 2);
        } else {
            bin.push_back ((major << 5) | 26);
            uint32 be = htonl (value);
            bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 4);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_encode::encode (binary_t& bin, cbor_major_t major, uint32 value)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (value < 24) {
            bin.push_back ((major << 5) | value);
        } else if (value < 0x100) {
            bin.push_back ((major << 5) | 24);
            bin.push_back (value);
        } else if (value < 0x10000) {
            bin.push_back ((major << 5) | 25);
            uint16 be = htons (value);
            bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 2);
        } else {
            bin.push_back ((major << 5) | 26);
            uint32 be = htonl (value);
            bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 4);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_encode::encode (binary_t& bin, int64 value)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        uint8 major = 0;
        if (value >= 0) {
            major = cbor_major_t::cbor_major_uint;
        } else {
            major = cbor_major_t::cbor_major_nint;
            value += 1;
            value = -value;
        }

        if (value < 24) {
            bin.push_back ((major << 5) | value);
        } else if (value < 0x100) {
            bin.push_back ((major << 5) | 24);
            bin.push_back (value);
        } else if (value < 0x10000) {
            bin.push_back ((major << 5) | 25);
            uint16 be = htons (value);
            bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 2);
        } else if (value < 0x100000000) {
            bin.push_back ((major << 5) | 26);
            uint32 be = htonl (value);
            bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 4);
        } else {
            bin.push_back ((major << 5) | 27);
            uint64 be = hton64 (value);
            bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 8);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_encode::encode (binary_t& bin, cbor_major_t major, uint64 value)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (value < 24) {
            bin.push_back ((major << 5) | value);
        } else if (value < 0x100) {
            bin.push_back ((major << 5) | 24);
            bin.push_back (value);
        } else if (value < 0x10000) {
            bin.push_back ((major << 5) | 25);
            uint16 be = htons (value);
            bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 2);
        } else if (value < 0x100000000) {
            bin.push_back ((major << 5) | 26);
            uint32 be = htonl (value);
            bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 4);
        } else {
            bin.push_back ((major << 5) | 27);
            uint64 be = hton64 (value);
            bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 8);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

#if defined __SIZEOF_INT128__
static uint8 contents_byte_length (uint128 data)
{
    uint8 i = 0;

    for (i = 16; i > 0; i--) {
        if (data >> (8 * (i - 1))) {
            break;
        }
    }
    return i;
}

return_t cbor_encode::encode (binary_t& bin, int128 value)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        uint8 major = 0;
        uint8 valueoftag = 0;

        if (value >= 0) {
            major = cbor_major_t::cbor_major_uint;
            valueoftag = cbor_tag_t::cbor_tag_positive_bignum;
        } else {
            major = cbor_major_t::cbor_major_nint;
            valueoftag = cbor_tag_t::cbor_tag_negative_bignum;
            value += 1;
            value = -value;
        }
        bool bignum = false;
        if (value >> 64) {
            bignum = true;
        }

        if (bignum) {
            uint8 len = contents_byte_length (value); // 128 / 8 = 16 always less than 24
            bin.push_back ((cbor_major_t::cbor_major_tag << 5) | valueoftag);
            bin.push_back ((cbor_major_t::cbor_major_bstr << 5) | len);
            uint128 be = hton128 (value);
            bin.insert (bin.end (), (byte_t*) &be + (16 - len), (byte_t*) &be + 16);
        } else {
            if (value < 24) {
                bin.push_back ((major << 5) | value);
            } else if (value < 0x100) {
                bin.push_back ((major << 5) | 24);
                bin.push_back (value);
            } else if (value < 0x10000) {
                bin.push_back ((major << 5) | 25);
                uint16 be = htons (value);
                bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 2);
            } else if (value < 0x100000000) {
                bin.push_back ((major << 5) | 26);
                uint32 be = htonl (value);
                bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 4);
            } else {
                bin.push_back ((major << 5) | 27);
                uint64 be = hton64 (value);
                bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 8);
            }
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_encode::encode (binary_t& bin, cbor_major_t major, uint128 value)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (value >> 64) {
            uint8 len = contents_byte_length (value); // 128 / 8 = 16 always less than 24
            bin.push_back ((cbor_major_t::cbor_major_tag << 5) | cbor_tag_t::cbor_tag_positive_bignum);
            bin.push_back ((cbor_major_t::cbor_major_bstr << 5) | len);
            uint128 be = hton128 (value);
            bin.insert (bin.end (), (byte_t*) &be + (16 - len), (byte_t*) &be + 16);
        } else {
            if (value < 24) {
                bin.push_back ((major << 5) | value);
            } else if (value < 0x100) {
                bin.push_back ((major << 5) | 24);
                bin.push_back (value);
            } else if (value < 0x10000) {
                bin.push_back ((major << 5) | 25);
                uint16 be = htons (value);
                bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 2);
            } else if (value < 0x100000000) {
                bin.push_back ((major << 5) | 26);
                uint32 be = htonl (value);
                bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 4);
            } else {
                bin.push_back ((major << 5) | 27);
                uint64 be = hton64 (value);
                bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 8);
            }
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}
#endif

return_t cbor_encode::encodefp16 (binary_t& bin, uint16 value)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        variant_t vt;
        uint32 be = 0;

        bin.push_back ((cbor_major_t::cbor_major_float << 5) | 25);
        be = htons (*(uint16*) &value);
        bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 2);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_encode::encode (binary_t& bin, float value)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        variant_t vt;
        uint32 be = 0;
        ieee754_format_as_small_as_possible (vt, value);

        switch (vt.type) {
            case vartype_t::TYPE_FP16:
                bin.push_back ((cbor_major_t::cbor_major_float << 5) | 25);
                be = htons (*(uint16*) &vt.data.ui16);
                bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 2);
                break;
            case vartype_t::TYPE_FLOAT:
                bin.push_back ((cbor_major_t::cbor_major_float << 5) | 26);
                be = htonl (*(uint32*) &vt.data.f);
                bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 4);
                break;
            default:
                break;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_encode::encode (binary_t& bin, double value)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        variant_t vt;
        uint64 be = 0;
        ieee754_format_as_small_as_possible (vt, value);

        switch (vt.type) {
            case vartype_t::TYPE_FP16:
                bin.push_back ((cbor_major_t::cbor_major_float << 5) | 25);
                be = htons (*(uint16*) &vt.data.ui16);
                bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 2);
                break;
            case vartype_t::TYPE_FLOAT:
                bin.push_back ((cbor_major_t::cbor_major_float << 5) | 26);
                be = htonl (*(uint32*) &vt.data.f);
                bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 4);
                break;
            case vartype_t::TYPE_DOUBLE:
                bin.push_back ((cbor_major_t::cbor_major_float << 5) | 27);
                be = hton64 (*(uint64*) &vt.data.d);
                bin.insert (bin.end (), (byte_t*) &be, (byte_t*) &be + 8);
                break;
            default:
                break;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_encode::encode (binary_t& bin, byte_t* value, size_t size)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        encode (bin, cbor_major_t::cbor_major_bstr, size);
        bin.insert (bin.end (), value, value + size);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_encode::encode (binary_t& bin, char* value)
{
    return_t ret = errorcode_t::success;
    size_t size = 0;

    if (nullptr != value) {
        size = strlen (value);
    }
    ret = encode (bin, value, size);
    return ret;
}

return_t cbor_encode::encode (binary_t& bin, char* value, size_t size)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == value) {
            uint8 major = cbor_major_t::cbor_major_simple;
            bin.push_back ((major << 5) | 22);
        } else {
            encode (bin, cbor_major_t::cbor_major_tstr, size);
            bin.insert (bin.end (), value, value + size);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t cbor_encode::encode (binary_t& bin, cbor_major_t major, cbor_control_t control, cbor_object* object)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 indefinite = (cbor_flag_t::cbor_indef & object->get_flags ());
        if (cbor_control_t::cbor_control_begin == control) {
            if (indefinite) {
                bin.push_back ((major << 5) | 31); // infinite-length
            } else {
                // 0xa0..0xb7 map
                encode (bin, major, object->size ());
            }
        } else if (cbor_control_t::cbor_control_end == control) {
            if (indefinite) {
                bin.push_back (0xff); // break
            }
        }
    }
    __finally2
    {
    }
    return ret;
}

return_t cbor_encode::encode (binary_t& bin, cbor_simple_t type, uint8 value)
{
    return_t ret = errorcode_t::success;

    switch (type) {
        case cbor_simple_t::cbor_simple_half_fp:
        case cbor_simple_t::cbor_simple_single_fp:
        case cbor_simple_t::cbor_simple_double_fp:
            ret = errorcode_t::request;
            break;
        default:
            if (value < 32) {
                bin.push_back ((cbor_major_t::cbor_major_simple << 5) | value);
            } else if (value < 0x100) {
                bin.push_back ((cbor_major_t::cbor_major_simple << 5) | 24);
                bin.push_back (value);
            }
            break;
    }
    return ret;
}

return_t cbor_encode::add_tag (binary_t& bin, cbor_object* object)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == object) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (object->tagged ()) {
            // a tag number (an integer in the range 0..2^(64)-1)
            encode (bin, cbor_major_t::cbor_major_tag, (uint64) object->tag_value ());
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

}
}
