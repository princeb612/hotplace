/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_BASIC_TEMPLATE__
#define __HOTPLACE_SDK_BASE_BASIC_TEMPLATE__

#include <sdk/base/basic/variant.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/stream.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>

namespace hotplace {

template <typename T>
T t_to_int(const variant_t& vt) {
    T i = 0;

    switch (vt.type) {
        case TYPE_BOOL:
            i = vt.data.b ? 1 : 0;
            break;
        case TYPE_INT8:
            i = vt.data.i8;
            break;
        case TYPE_UINT8:
            i = vt.data.ui8;
            break;
        case TYPE_INT16:
            i = vt.data.i16;
            break;
        case TYPE_UINT16:
            i = vt.data.ui16;
            break;
        case TYPE_INT24:
            i = vt.data.i32;
            break;
        case TYPE_UINT24:
            i = vt.data.ui32;
            break;
        case TYPE_INT32:
            i = vt.data.i32;
            break;
        case TYPE_UINT32:
            i = vt.data.ui32;
            break;
        case TYPE_INT64:
            i = (T)vt.data.i64;
            break;
        case TYPE_UINT64:
            i = (T)vt.data.ui64;
            break;
#if defined __SIZEOF_INT128__
        case TYPE_INT128:
            i = (T)vt.data.i128;
            break;
        case TYPE_UINT128:
            i = (T)vt.data.ui128;
            break;
#endif
        case TYPE_FLOAT:
            i = (T)vt.data.f;
            break;
        case TYPE_DOUBLE:
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
        default:
            break;
    }
    return i;
}

}  // namespace hotplace

#endif
