/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   variant.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026.05.23   Soo Han and Gemini  Refined with guidance and collaboration from Gemini
 *
 * @note    Unified Type-Safe Variant Implementation (Refactored with Gemini)
 *
 * @details
 *          Gemini mentioned ...
 *
 *          [The Great Refactoring]
 *          - Before: A nightmare of boilerplate. Every single type demanded its own
 *                    constructor, operator=, and set() function, leading to a massive,
 *                    hard-to-maintain codebase.
 *          - After : Refactored into a sleek, modern template architecture with Gemini.
 *                    By shifting type metadata into `variant_traits` and leveraging SFINAE
 *                    (`std::enable_if`), we consolidated hundreds of lines of redundant
 *                    overloads into unified single-entry template functions.
 *
 *          Safe, robust, and completely cross-platform (MSVC, MinGW, and GCC approved).
 */

#include <stdarg.h>

#include <hotplace/sdk/base/basic/base16.hpp>
#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/string/string.hpp>
#include <hotplace/sdk/base/system/bignumber.hpp>
#include <hotplace/sdk/base/system/datetime.hpp>
#include <hotplace/sdk/base/system/endian.hpp>
#include <hotplace/sdk/base/system/ieee754.hpp>
#include <hotplace/sdk/base/system/types.hpp>
#include <hotplace/sdk/base/types.hpp>
#include <ostream>

namespace hotplace {

variant_t::variant_t() : type(TYPE_NULL), size(0), flag(0) { memset(&data, 0, sizeof(data)); }

variant_t::variant_t(const variant_t& other) : type(TYPE_NULL), size(0), flag(0) { *this = other; }

variant_t::variant_t(variant_t&& other) : type(TYPE_NULL), size(0), flag(0) { *this = std::move(other); }

variant_t::~variant_t() { clear(); }

variant_t& variant_t::operator=(const variant_t& other) {
    clear();

    type = other.type;
    if (variant_flag_t::vt_flag_free & other.flag) {
        switch (other.type) {
            case TYPE_BINARY:
            case TYPE_NSTRING:
            case TYPE_BIGNUMBER:
                data.bstr = (unsigned char*)malloc(other.size + 1);
                memcpy(data.bstr, other.data.bstr, other.size);
                break;
            case TYPE_STRING:
                data.str = strdup(other.data.str);
                break;
            case TYPE_DATETIME:
                data.dt = (datetime_t*)malloc(sizeof(datetime_t));
                memcpy(data.dt, other.data.dt, sizeof(datetime_t));
                break;
            default:
                break;
        }
    } else {
        memcpy(&data, &other.data, sizeof(data));
    }
    size = other.size;
    flag = other.flag;

    return *this;
}

variant_t& variant_t::operator=(variant_t&& other) {
    if (this != &other) {
        clear();

        std::swap(type, other.type);
        std::swap(data, other.data);
        std::swap(size, other.size);
        std::swap(flag, other.flag);
    }
    return *this;
}

variant_t& variant_t::reset() {
    type = TYPE_NULL;
    memset(&data, 0, sizeof(data));
    size = 0;
    flag = 0;

    return *this;
}

variant_t& variant_t::clear() {
    if (variant_flag_t::vt_flag_free & flag) {
        free(data.p);
    }

    type = TYPE_NULL;
    memset(&data, 0, sizeof(data));
    size = 0;
    flag = 0;

    return *this;
}

variant::variant() {}

variant::variant(const variant& value) : _vt(value._vt) {}

variant::variant(variant&& value) : _vt(std::move(value._vt)) {}

variant::variant(const variant_t& value) : _vt(value) {}

variant::variant(variant_t&& value) : _vt(std::move(value)) {}

variant::variant(const char* value) { set_str_new(value); }

variant::variant(const uint24_t& value) { set_uint24(value); }

variant::variant(const uint48_t& value) { set_uint48(value); }

variant::variant(vartype_t vtype, void* value) { set_user_type(vtype, value); }

variant::variant(const std::string& value) { set_new((char*)value.c_str(), value.size()); }

variant::variant(const binary_t& value) { set_new((byte_t*)value.data(), value.size()); }

variant::variant(const stream_t* value) { set_stream(value); }

variant::variant(const datetime_t& value) { set_datetime(value); }

variant::variant(const bignumber& value) { set_bn(value); }

variant::~variant() { _vt.clear(); }

const variant_t& variant::content() const { return _vt; }

variant_t& variant::get() { return _vt; }

vartype_t variant::type() const { return _vt.type; }

size_t variant::size() const { return _vt.size; }

uint16 variant::flag() const { return _vt.flag; }

variant& variant::set_flag(uint16 flag) {
    _vt.flag |= flag;
    return *this;
}

variant& variant::unset_flag(uint16 flag) {
    _vt.flag &= ~flag;
    return *this;
}

variant& variant::reset() {
    _vt.reset();
    return *this;
}

variant& variant::clear() {
    _vt.clear();
    return *this;
}

variant& variant::set_int24(int32 value) {
    _vt.type = TYPE_INT24;
    _vt.data.i32 = (value & 0x00ffffff);
    _vt.size = RTL_FIELD_SIZE(uint24_t, data);
    _vt.flag = vt_flag_int;
    return *this;
}

variant& variant::set_uint24(uint32 value) {
    _vt.type = TYPE_UINT24;
    _vt.data.ui32 = (value & 0x00ffffff);
    _vt.size = RTL_FIELD_SIZE(uint24_t, data);
    _vt.flag = vt_flag_int;
    return *this;
}

variant& variant::set_uint24(const byte_t* p, size_t len) {
    _vt.type = TYPE_UINT24;
    b24_i32(p, len, _vt.data.ui32);
    _vt.size = RTL_FIELD_SIZE(uint24_t, data);
    _vt.flag = vt_flag_int;
    return *this;
}

variant& variant::set_uint24(const uint24_t& value) {
    _vt.type = TYPE_UINT24;
    b24_i32(value, _vt.data.ui32);
    _vt.size = RTL_FIELD_SIZE(uint24_t, data);
    _vt.flag = vt_flag_int;
    return *this;
}

variant& variant::set_int48(int64 value) {
    _vt.type = TYPE_INT48;
    _vt.data.i64 = (value & 0x0000ffffffffffff);
    _vt.size = RTL_FIELD_SIZE(uint48_t, data);
    _vt.flag = vt_flag_int;
    return *this;
}

variant& variant::set_uint48(uint64 value) {
    _vt.type = TYPE_UINT48;
    _vt.data.ui64 = (value & 0x0000ffffffffffff);
    _vt.size = RTL_FIELD_SIZE(uint48_t, data);
    _vt.flag = vt_flag_int;
    return *this;
}

variant& variant::set_uint48(const byte_t* p, size_t len) {
    _vt.type = TYPE_UINT48;
    b48_i64(p, len, _vt.data.ui64);
    _vt.size = RTL_FIELD_SIZE(uint48_t, data);
    _vt.flag = vt_flag_int;
    return *this;
}

variant& variant::set_uint48(const uint48_t& value) {
    _vt.type = TYPE_UINT48;
    b48_i64(value, _vt.data.ui64);
    _vt.size = RTL_FIELD_SIZE(uint48_t, data);
    _vt.flag = vt_flag_int;
    return *this;
}

variant& variant::set_fp16(uint16 value) {
    _vt.type = TYPE_FP16;
    _vt.data.ui16 = (value);
    _vt.size = sizeof(uint16);
    _vt.flag = vt_flag_float;
    return *this;
}

variant& variant::set_bin32(uint32 value) { return set(fp32_from_binary32(value)); }

variant& variant::set_bin64(uint64 value) { return set(fp64_from_binary64(value)); }

variant& variant::set_user_type(vartype_t vtype, void* value) {
    _vt.type = vtype;
    _vt.data.p = value;
    _vt.size = 0;
    _vt.flag = vt_flag_user_type;
    return *this;
}

variant& variant::set_str_new(const char* value) {
    _vt.type = TYPE_STRING;
    _vt.size = 0;
    _vt.flag = vt_flag_string;
    char* p = nullptr;
    if (value) {
        p = strdup(value);
        if (p) {
            _vt.data.str = p;
            _vt.flag |= variant_flag_t::vt_flag_free;
        }
    }
    _vt.data.str = p;
    return *this;
}

variant& variant::set_string(const std::string& value) {
    _vt.type = TYPE_STRING;
    _vt.size = 0;
    _vt.flag = vt_flag_string;
    char* p = strdup(value.c_str());
    if (p) {
        _vt.data.str = p;
        _vt.flag |= variant_flag_t::vt_flag_free;
        _vt.size = value.size();
    }
    _vt.data.str = p;
    return *this;
}

variant& variant::set_binary(const binary_t& bin) {
    _vt.type = TYPE_BINARY;
    _vt.size = 0;
    _vt.flag = vt_flag_binary;
    unsigned char* p = nullptr;
    size_t n = bin.size();
    if (n) {
        p = (unsigned char*)malloc(n + 1);
        if (p) {
            memcpy(p, bin.data(), n);
            *(p + n) = 0;
            _vt.size = n;
            _vt.flag |= variant_flag_t::vt_flag_free;
        }
    }
    _vt.data.bstr = p;
    return *this;
}

variant& variant::set_stream(const stream_t* s) {
    _vt.type = TYPE_BINARY;
    _vt.size = 0;
    _vt.flag = vt_flag_binary;
    unsigned char* p = nullptr;
    if (s) {
        const byte_t* value = s->data();
        size_t n = s->size();
        if (n) {
            p = (unsigned char*)malloc(n + 1);
            if (p) {
                memcpy(p, value, n);
                *(p + n) = 0;
                _vt.size = n;
                _vt.flag |= variant_flag_t::vt_flag_free;
            }
        }
    }
    _vt.data.bstr = p;
    return *this;
}

variant& variant::set_datetime(const datetime_t& value) {
    _vt.type = TYPE_DATETIME;
    _vt.size = sizeof(datetime_t);
    _vt.flag = 0;
    datetime_t* p = (datetime_t*)malloc(sizeof(datetime_t));
    if (p) {
        memcpy(p, &value, sizeof(datetime_t));
        _vt.flag |= variant_flag_t::vt_flag_free;
    }
    _vt.data.dt = p;

    return *this;
}

variant& variant::set_bn(const bignumber& value) {
    binary_t bin;
    value >> bin;

    _vt.type = TYPE_BIGNUMBER;
    auto size = bin.size();
    if (false == bin.empty()) {
        _vt.data.bstr = (unsigned char*)malloc(size + 1);
        memcpy(_vt.data.bstr, bin.data(), size);
        _vt.size = size;
        _vt.flag = vt_flag_binary | vt_flag_free;
    }
    if (value < 0) {
        _vt.flag |= vt_flag_negative;
    }

    return *this;
}

variant& variant::set_bn(const unsigned char* p, size_t n) { return set_bn(bignumber(p, n)); }

const std::string variant::to_str() const {
    std::string ret_value;
    to_string(ret_value);
    return ret_value;
}

const std::string variant::to_hex() const {
    binary_t bin;
    std::string ret_value;
    to_binary(bin);
    base16_encode(bin, ret_value);
    return ret_value;
}

const binary_t variant::to_bin(uint32 flags) const {
    binary_t bin;
    to_binary(bin, flags);
    return bin;
}

int variant::to_int() const { return t_toi<int>(); }

return_t variant::to_binary(binary_t& target, uint32 flags) const {
    return_t ret = errorcode_t::success;

    bool change_endian = (variant_convendian & flags);

    if (variant_trunc & flags) {
        target.clear();
    }

    switch (_vt.type) {
        case TYPE_INT8:
        case TYPE_UINT8:
            binary_push(target, _vt.data.ui8);
            break;
        case TYPE_INT16:
        case TYPE_UINT16:
        case TYPE_FP16:
            if (change_endian) {
                binary_append(target, _vt.data.ui16, hton16);
            } else {
                binary_append(target, _vt.data.ui16);
            }
            break;
        case TYPE_INT24:
        case TYPE_UINT24: {
            uint24_t temp;
            i32_b24(temp, _vt.data.ui32);
            binary_append(target, temp.data, RTL_FIELD_SIZE(uint24_t, data));
        } break;
        case TYPE_INT32:
        case TYPE_UINT32:
            if (change_endian) {
                binary_append(target, _vt.data.ui32, hton32);
            } else {
                binary_append(target, _vt.data.ui32);
            }
            break;
        case TYPE_INT48:
        case TYPE_UINT48: {
            uint48_t temp;
            i64_b48(temp, _vt.data.ui64);
            binary_append(target, temp.data, RTL_FIELD_SIZE(uint48_t, data));
        } break;
        case TYPE_INT64:
        case TYPE_UINT64:
            if (change_endian) {
                binary_append(target, _vt.data.ui64, hton64);
            } else {
                binary_append(target, _vt.data.ui64);
            }
            break;
#if defined __SIZEOF_INT128__
        case TYPE_INT128:
        case TYPE_UINT128:
            if (change_endian) {
                binary_append(target, _vt.data.ui128, hton128);
            } else {
                binary_append(target, _vt.data.ui128);
            }
            break;
#endif
        case TYPE_FLOAT: {
            auto ui32 = binary32_from_fp32(_vt.data.f);
            if (change_endian) {
                binary_append(target, ui32, hton32);
            } else {
                binary_append(target, ui32);
            }
        } break;
        case TYPE_DOUBLE: {
            auto ui64 = binary64_from_fp64(_vt.data.d);
            if (change_endian) {
                binary_append(target, ui64, hton64);
            } else {
                binary_append(target, ui64);
            }
        } break;
        case TYPE_STRING:
            binary_append(target, _vt.data.str);
            break;
        case TYPE_BINARY:
        case TYPE_NSTRING:
        case TYPE_BIGNUMBER:
            binary_append(target, _vt.data.bstr, _vt.size);
            break;
        default:
            ret = errorcode_t::not_supported;
            break;
    }

    return ret;
}

return_t variant::to_string(std::string& target) const {
    return_t ret = errorcode_t::success;

    target.clear();
    switch (_vt.type) {
        case TYPE_NULL:
            target = "null";
            break;
        case TYPE_BOOL: {
            target = _vt.data.b ? "true" : "false";
        } break;
        case TYPE_CHAR:
        case TYPE_BYTE: {
            if (isprint(_vt.data.c)) {
                target.assign(&_vt.data.c, 1);
            } else {
                target = ".";
            }
        } break;
        case TYPE_INT8:
            target = format("%i", _vt.data.i8);
            break;
        case TYPE_UINT8:
            target = format("%u", _vt.data.ui8);
            break;
        case TYPE_INT16:
            target = format("%i", _vt.data.i16);
            break;
        case TYPE_UINT16:
            target = format("%u", _vt.data.ui16);
            break;
        case TYPE_INT24:
        case TYPE_INT32:
            target = format("%i", _vt.data.i32);
            break;
        case TYPE_UINT24:
        case TYPE_UINT32:
            target = format("%u", _vt.data.ui32);
            break;
        case TYPE_INT48:
        case TYPE_INT64: {
            basic_stream bs;
            bs.printf("%I64i", _vt.data.i64);
            target << bs;
        } break;
        case TYPE_UINT48:
        case TYPE_UINT64: {
            basic_stream bs;
            bs.printf("%I64u", _vt.data.ui64);
            target << bs;
        } break;
#if defined __SIZEOF_INT128__
        case TYPE_INT128: {
            basic_stream bs;
            bs.printf("%I128i", _vt.data.i128);
            target << bs;
        } break;
        case TYPE_UINT128: {
            basic_stream bs;
            bs.printf("%I128u", _vt.data.ui128);
            target << bs;
        } break;
#endif
        case TYPE_FP16: {
            basic_stream bs;
            float f = float_from_fp16(_vt.data.ui16);
            bs.printf("%f", f);
            target << bs;
        } break;
        case TYPE_FLOAT: {
            basic_stream bs;
            bs.printf("%f", _vt.data.f);
            target << bs;
        } break;
        case TYPE_DOUBLE: {
            basic_stream bs;
            bs.printf("%lf", _vt.data.d);
            target << bs;
        } break;
        case TYPE_STRING:
            if (_vt.data.str) {
                target = _vt.data.str;
            }
            break;
        case TYPE_NSTRING:
            if (_vt.data.str) {
                target.assign(_vt.data.str, _vt.size);
            }
            break;
        case TYPE_BINARY:
        case TYPE_BIGNUMBER: {
            if (_vt.data.str) {
                target.clear();
                uint32 i = 0;
                char* p = nullptr;
                for (i = 0, p = _vt.data.str; i < _vt.size; i++, p++) {
                    if (isprint(*p)) {
                        target.append(p, 1);
                    } else {
                        target.append(".");
                    }
                }
            }
        } break;
        default:
            ret = errorcode_t::mismatch;
            break;
    }
    return ret;
}

variant& variant::operator=(const variant& other) {
    _vt = other._vt;
    return *this;
}

variant& variant::operator=(variant&& other) {
    if (this != &other) {
        _vt = std::move(other._vt);
    }
    return *this;
}

variant& variant::operator=(const variant_t& other) {
    _vt = other;
    return *this;
}

variant& variant::operator=(variant_t&& other) {
    _vt = std::move(other);
    return *this;
}

variant& variant::operator=(const uint24_t& value) { return set_uint24(value); }

variant& variant::operator=(const uint48_t& value) { return set_uint48(value); }

variant& variant::operator=(const std::string& value) { return set_string(value); }

variant& variant::operator=(const binary_t& value) { return set_binary(value); }

variant& variant::operator=(const datetime_t& value) { return set_datetime(value); }

variant& variant::operator=(const bignumber& other) { return set_bn(other); }

}  // namespace hotplace
