/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_INTEGER__
#define __HOTPLACE_SDK_BASE_NOSTD_INTEGER__

#include <sdk/base/basic/binary.hpp>
#include <sdk/base/basic/types.hpp>
#include <sdk/base/basic/variant.hpp>

namespace hotplace {

template <typename T>
T t_to_int(const variant_t& vt, return_t& errorcode) {
    errorcode = errorcode_t::success;
    size_t tsize = sizeof(T);
    size_t vsize = 0;
    T i = 0;  // i = T();

    switch (vt.type) {
        case TYPE_BOOL:
            vsize = RTL_FIELD_SIZE(vartype_union, b);
            i = vt.data.b ? 1 : 0;
            break;
        case TYPE_INT8:
            vsize = RTL_FIELD_SIZE(vartype_union, i8);
            i = vt.data.i8;
            break;
        case TYPE_UINT8:
            vsize = RTL_FIELD_SIZE(vartype_union, ui8);
            i = vt.data.ui8;
            break;
        case TYPE_INT16:
            vsize = RTL_FIELD_SIZE(vartype_union, i16);
            i = vt.data.i16;
            break;
        case TYPE_UINT16:
            vsize = RTL_FIELD_SIZE(vartype_union, i16);
            i = vt.data.ui16;
            break;
        case TYPE_INT24:
            vsize = RTL_FIELD_SIZE(vartype_union, i32);
            i = vt.data.i32;
            break;
        case TYPE_UINT24:
            vsize = RTL_FIELD_SIZE(vartype_union, ui32);
            i = vt.data.ui32;
            break;
        case TYPE_INT32:
            vsize = RTL_FIELD_SIZE(vartype_union, i32);
            i = vt.data.i32;
            break;
        case TYPE_UINT32:
            vsize = RTL_FIELD_SIZE(vartype_union, ui32);
            i = vt.data.ui32;
            break;
        case TYPE_INT48:
            vsize = RTL_FIELD_SIZE(vartype_union, i64);
            i = vt.data.i64;
            break;
        case TYPE_UINT48:
            vsize = RTL_FIELD_SIZE(vartype_union, ui64);
            i = vt.data.ui64;
            break;
        case TYPE_INT64:
            vsize = RTL_FIELD_SIZE(vartype_union, i64);
            i = (T)vt.data.i64;
            break;
        case TYPE_UINT64:
            vsize = RTL_FIELD_SIZE(vartype_union, ui64);
            i = (T)vt.data.ui64;
            break;
#if defined __SIZEOF_INT128__
        case TYPE_INT128:
            vsize = RTL_FIELD_SIZE(vartype_union, i128);
            i = (T)vt.data.i128;
            break;
        case TYPE_UINT128:
            vsize = RTL_FIELD_SIZE(vartype_union, ui128);
            i = (T)vt.data.ui128;
            break;
#endif
        case TYPE_FLOAT:
            vsize = RTL_FIELD_SIZE(vartype_union, f);
            i = (T)vt.data.f;
            break;
        case TYPE_DOUBLE:
            vsize = RTL_FIELD_SIZE(vartype_union, d);
            i = (T)vt.data.d;
            break;
        case TYPE_STRING:
        case TYPE_NSTRING:
            if (vt.size) {
                i = atoi(std::string(vt.data.str, vt.size).c_str());
            } else {
                i = atoi(vt.data.str);
            }
            break;
        case TYPE_BINARY:
            i = t_binary_to_integer<T>(vt.data.bstr, vt.size, errorcode);
            break;
        default:
            break;
    }
    if (vsize > tsize) {
        errorcode = errorcode_t::narrow_type;
    }
    return i;
}

template <typename T>
T t_to_int(const variant_t& vt) {
    return_t errorcode = errorcode_t::success;
    return t_to_int<T>(vt, errorcode);
}

template <typename T>
T t_to_int(const variant& v) {
    return_t errorcode = errorcode_t::success;
    return t_to_int<T>(v.content(), errorcode);
}

}  // namespace hotplace

#endif
