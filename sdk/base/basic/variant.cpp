/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <stdarg.h>

#include <hotplace/sdk/base/basic/base16.hpp>
#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/base/basic/ieee754.hpp>
#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/nostd/integer.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/string/string.hpp>
#include <hotplace/sdk/base/system/endian.hpp>
#include <hotplace/sdk/base/system/types.hpp>
#include <ostream>

namespace hotplace {

variant::variant() {}

variant::variant(const void *value) { set_pointer(value); }

variant::variant(const char *value) { set_str_new(value); }

variant::variant(const char *value, size_t n) { set_strn_new(value, n); }

variant::variant(const unsigned char *value, size_t n) { set_bstr_new(value, n); }

variant::variant(const std::string &rhs) { set_strn_new(rhs.c_str(), rhs.size()); }

variant::variant(const binary_t &rhs) { set_bstr_new(rhs.empty() ? nullptr : &rhs[0], rhs.size()); }

variant::variant(const stream_t *rhs) { set_bstr_new(rhs); }

variant::variant(bool value) { set_bool(value); }

variant::variant(int8 value) { set_int8(value); }

variant::variant(uint8 value) { set_uint8(value); }

variant::variant(int16 value) { set_int16(value); }

variant::variant(uint16 value) { set_uint16(value); }

variant::variant(const uint24_t &value) { set_uint24(value); }

variant::variant(int32 value) { set_int32(value); }

variant::variant(uint32 value) { set_uint32(value); }

variant::variant(const uint48_t &value) { set_uint48(value); }

variant::variant(int64 value) { set_int64(value); }

variant::variant(uint64 value) { set_uint64(value); }

#if defined __SIZEOF_INT128__
variant::variant(int128 value) { set_int128(value); }

variant::variant(uint128 value) { set_uint128(value); }
#endif

variant::variant(float value) { set_float(value); }

variant::variant(double value) { set_double(value); }

variant::variant(const datetime_t &value) { set_datetime(value); }

variant::variant(const variant_t &rhs) : _vt(rhs) {}

variant::variant(variant_t &&rhs) : _vt(std::move(rhs)) {}

variant::variant(const variant &rhs) : _vt(rhs._vt) {}

variant::variant(variant &&rhs) : _vt(std::move(rhs._vt)) {}

variant::~variant() { _vt.clear(); }

const variant_t &variant::content() const { return _vt; }

vartype_t variant::type() const { return _vt.type; }

uint16 variant::size() const { return _vt.size; }

uint16 variant::flag() const { return _vt.flag; }

/**
 * @brief reset
 * @example
 *      vt.reset().set_bool(true);
 */
variant &variant::clear() {
    if (variant_flag_t::flag_free & _vt.flag) {
        free(_vt.data.p);
    }

    _vt.type = TYPE_NULL;
    memset(&_vt.data, 0, RTL_FIELD_SIZE(variant_t, data));
    _vt.size = 0;
    _vt.flag = 0;
    return *this;
}

variant &variant::set_flag(uint8 flag) {
    _vt.flag |= flag;
    return *this;
}

variant &variant::unset_flag(uint8 flag) {
    _vt.flag &= ~flag;
    return *this;
}

variant &variant::set_pointer(const void *value) {
    _vt.type = TYPE_POINTER;
    _vt.data.p = (void *)value;
    _vt.size = sizeof(void *);
    _vt.flag = flag_pointer;
    return *this;
}

variant &variant::set_bool(bool value) {
    _vt.type = TYPE_BOOL;
    _vt.data.b = (value);
    _vt.size = sizeof(bool);
    _vt.flag = flag_bool;
    return *this;
}

variant &variant::set_int8(int8 value) {
    _vt.type = TYPE_INT8;
    _vt.data.i8 = (value);
    _vt.size = sizeof(int8);
    _vt.flag = flag_int;
    return *this;
}

variant &variant::set_uint8(uint8 value) {
    _vt.type = TYPE_UINT8;
    _vt.data.ui8 = (value);
    _vt.size = sizeof(uint8);
    _vt.flag = flag_int;
    return *this;
}

variant &variant::set_int16(int16 value) {
    _vt.type = TYPE_INT16;
    _vt.data.i16 = (value);
    _vt.size = sizeof(uint16);
    _vt.flag = flag_int;
    return *this;
}

variant &variant::set_uint16(uint16 value) {
    _vt.type = TYPE_UINT16;
    _vt.data.ui16 = (value);
    _vt.size = sizeof(uint16);
    _vt.flag = flag_int;
    return *this;
}

variant &variant::set_int24(int32 value) {
    _vt.type = TYPE_INT24;
    _vt.data.i32 = (value & 0x00ffffff);
    _vt.size = RTL_FIELD_SIZE(uint24_t, data);
    _vt.flag = flag_int;
    return *this;
}

variant &variant::set_uint24(uint32 value) {
    _vt.type = TYPE_UINT24;
    _vt.data.ui32 = (value & 0x00ffffff);
    _vt.size = RTL_FIELD_SIZE(uint24_t, data);
    _vt.flag = flag_int;
    return *this;
}

variant &variant::set_uint24(const byte_t *p, size_t len) {
    _vt.type = TYPE_UINT24;
    b24_i32(p, len, _vt.data.ui32);
    _vt.size = RTL_FIELD_SIZE(uint24_t, data);
    _vt.flag = flag_int;
    return *this;
}

variant &variant::set_uint24(const uint24_t &value) {
    _vt.type = TYPE_UINT24;
    b24_i32(value, _vt.data.ui32);
    _vt.size = RTL_FIELD_SIZE(uint24_t, data);
    _vt.flag = flag_int;
    return *this;
}

variant &variant::set_int32(int32 value) {
    _vt.type = TYPE_INT32;
    _vt.data.i32 = (value);
    _vt.size = sizeof(int32);
    _vt.flag = flag_int;
    return *this;
}

variant &variant::set_uint32(uint32 value) {
    _vt.type = TYPE_UINT32;
    _vt.data.ui32 = (value);
    _vt.size = sizeof(uint32);
    _vt.flag = flag_int;
    return *this;
}

variant &variant::set_int48(int64 value) {
    _vt.type = TYPE_INT48;
    _vt.data.i64 = (value & 0x0000ffffffffffff);
    _vt.size = RTL_FIELD_SIZE(uint48_t, data);
    _vt.flag = flag_int;
    return *this;
}

variant &variant::set_uint48(uint64 value) {
    _vt.type = TYPE_UINT48;
    _vt.data.ui64 = (value & 0x0000ffffffffffff);
    _vt.size = RTL_FIELD_SIZE(uint48_t, data);
    _vt.flag = flag_int;
    return *this;
}

variant &variant::set_uint48(const byte_t *p, size_t len) {
    _vt.type = TYPE_UINT48;
    b48_i64(p, len, _vt.data.ui64);
    _vt.size = RTL_FIELD_SIZE(uint48_t, data);
    _vt.flag = flag_int;
    return *this;
}

variant &variant::set_uint48(const uint48_t &value) {
    _vt.type = TYPE_UINT48;
    b48_i64(value, _vt.data.ui64);
    _vt.size = RTL_FIELD_SIZE(uint48_t, data);
    _vt.flag = flag_int;
    return *this;
}

variant &variant::set_int64(int64 value) {
    _vt.type = TYPE_INT64;
    _vt.data.i64 = (value);
    _vt.size = sizeof(int64);
    _vt.flag = flag_int;
    return *this;
}

variant &variant::set_uint64(uint64 value) {
    _vt.type = TYPE_UINT64;
    _vt.data.ui64 = (value);
    _vt.size = sizeof(uint64);
    _vt.flag = flag_int;
    return *this;
}

#if defined __SIZEOF_INT128__
variant &variant::set_int128(int128 value) {
    _vt.type = TYPE_INT128;
    _vt.data.i128 = (value);
    _vt.size = sizeof(int128);
    _vt.flag = flag_int;
    return *this;
}

variant &variant::set_uint128(uint128 value) {
    _vt.type = TYPE_UINT128;
    _vt.data.ui128 = (value);
    _vt.size = sizeof(uint128);
    _vt.flag = flag_int;
    return *this;
}
#endif

variant &variant::set_fp16(uint16 value) {
    _vt.type = TYPE_FP16;
    _vt.data.ui16 = (value);
    _vt.size = sizeof(uint16);
    _vt.flag = flag_float;
    return *this;
}

variant &variant::set_fp32(float value) {
    _vt.type = TYPE_FLOAT;
    _vt.data.f = (value);
    _vt.size = sizeof(float);
    _vt.flag = flag_float;
    return *this;
}

variant &variant::set_float(float value) { return set_fp32(value); }

variant &variant::set_fp64(double value) {
    _vt.type = TYPE_DOUBLE;
    _vt.data.d = (value);
    _vt.size = sizeof(double);
    _vt.flag = flag_float;
    return *this;
}

variant &variant::set_double(double value) { return set_fp64(value); }

variant &variant::set_datetime(const datetime_t &value) {
    _vt.type = TYPE_DATETIME;
    _vt.size = sizeof(datetime_t);
    _vt.flag = flag_datetime;
    datetime_t *p = (datetime_t *)malloc(sizeof(datetime_t));
    if (p) {
        memcpy(p, &value, sizeof(datetime_t));
        _vt.flag |= variant_flag_t::flag_free;
    }
    _vt.data.dt = p;

    return *this;
}

variant &variant::set_str(const char *value) {
    _vt.type = TYPE_STRING;
    _vt.data.str = (char *)value;
    _vt.size = 0;
    _vt.flag = flag_string;
    return *this;
}

variant &variant::set_nstr(const char *value, size_t n) {
    _vt.type = TYPE_NSTRING;
    _vt.data.str = (char *)value;
    _vt.size = n;
    _vt.flag = flag_string;
    return *this;
}

variant &variant::set_bstr(const unsigned char *value, size_t n) {
    _vt.type = TYPE_BINARY;
    _vt.data.bstr = (unsigned char *)value;
    _vt.size = n;
    _vt.flag = flag_binary;
    return *this;
}

variant &variant::set_user_type(vartype_t vtype, void *value) {
    _vt.type = vtype;
    _vt.data.p = value;
    _vt.size = 0;
    _vt.flag = flag_user_type;
    return *this;
}

variant &variant::set_str_new(const char *value) {
    _vt.type = TYPE_STRING;
    _vt.size = 0;
    _vt.flag = flag_string;
    char *p = nullptr;
    if (value) {
        p = strdup(value);
        if (p) {
            _vt.data.str = p;
            _vt.flag |= variant_flag_t::flag_free;
        }
    }
    _vt.data.str = p;
    return *this;
}

variant &variant::set_str_new(const std::string &value) {
    _vt.type = TYPE_STRING;
    _vt.size = 0;
    _vt.flag = flag_string;
    char *p = strdup(value.c_str());
    if (p) {
        _vt.data.str = p;
        _vt.flag |= variant_flag_t::flag_free;
        _vt.size = value.size();
    }
    _vt.data.str = p;
    return *this;
}

variant &variant::set_strn_new(const char *value, size_t n) {
    _vt.type = TYPE_STRING;
    _vt.size = 0;
    _vt.flag = flag_string;
    char *p = nullptr;
    if (n) {
        p = (char *)malloc(n + 1);
        if (p) {
            strncpy(p, value, n);
            *(p + n) = 0;
            _vt.size = n;
            _vt.flag |= variant_flag_t::flag_free;
        }
    }
    _vt.data.str = p;
    return *this;
}

variant &variant::set_bstr_new(const unsigned char *value, size_t n) {
    _vt.type = TYPE_BINARY;
    _vt.size = 0;
    _vt.flag = flag_binary;
    unsigned char *p = nullptr;
    if (n) {
        p = (unsigned char *)malloc(n + 1);
        if (p) {
            memcpy(p, value, n);
            *(p + n) = 0;
            _vt.size = n;
            _vt.flag |= variant_flag_t::flag_free;
        }
    }
    _vt.data.bstr = p;
    return *this;
}

variant &variant::set_bstr_new(const stream_t *s) {
    _vt.type = TYPE_BINARY;
    _vt.size = 0;
    _vt.flag = flag_binary;
    unsigned char *p = nullptr;
    if (s) {
        const byte_t *value = s->data();
        size_t n = s->size();
        if (n) {
            p = (unsigned char *)malloc(n + 1);
            if (p) {
                memcpy(p, value, n);
                *(p + n) = 0;
                _vt.size = n;
                _vt.flag |= variant_flag_t::flag_free;
            }
        }
    }
    _vt.data.bstr = p;
    return *this;
}

variant &variant::set_nstr_new(const char *value, size_t n) {
    _vt.type = TYPE_NSTRING;
    _vt.size = 0;
    _vt.flag = flag_string;
    char *p = nullptr;
    if (n) {
        p = (char *)malloc(n + 1);
        if (p) {
            strncpy(p, value, n);
            *(p + n) = 0;
            _vt.size = n;
            _vt.flag |= variant_flag_t::flag_free;
        }
    }
    _vt.data.str = p;
    return *this;
}

variant &variant::set_binary_new(const binary_t &bin) {
    _vt.type = TYPE_BINARY;
    _vt.size = 0;
    _vt.flag = flag_binary;
    unsigned char *p = nullptr;
    size_t n = bin.size();
    if (n) {
        p = (unsigned char *)malloc(n + 1);
        if (p) {
            memcpy(p, &bin[0], n);
            *(p + n) = 0;
            _vt.size = n;
            _vt.flag |= variant_flag_t::flag_free;
        }
    }
    _vt.data.bstr = p;
    return *this;
}

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

int variant::to_int() const { return t_to_int<int>(_vt); }

return_t variant::to_binary(binary_t &target, uint32 flags) const {
    return_t ret = errorcode_t::success;

    bool change_endian = (variant_convendian & flags);

    if (variant_trunc & flags) {
        target.clear();
    }

    byte_t *p = nullptr;
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
        case TYPE_FLOAT:
            if (change_endian) {
                binary_append(target, _vt.data.f, hton32);
            } else {
                binary_append(target, _vt.data.f);
            }
            break;
        case TYPE_DOUBLE:
            if (change_endian) {
                binary_append(target, _vt.data.d, hton64);
            } else {
                binary_append(target, _vt.data.d);
            }
            break;
        case TYPE_STRING:
            binary_append(target, _vt.data.str);
            break;
        case TYPE_BINARY:
        case TYPE_NSTRING:
            binary_append(target, _vt.data.bstr, _vt.size);
            break;
        default:
            ret = errorcode_t::not_supported;
            break;
    }

    return ret;
}

return_t variant::to_string(std::string &target) const {
    return_t ret = errorcode_t::success;

    target.clear();
    switch (_vt.type) {
        case TYPE_NULL:
            target = "null";
            break;
        case TYPE_BOOLEAN:
        case TYPE_BOOL: {
            target = _vt.data.b ? "true" : "false";
        } break;
#if 1
        case TYPE_CHAR:
        case TYPE_BYTE: {
            if (isprint(_vt.data.c)) {
                target.assign(&_vt.data.c, 1);
            } else {
                target = ".";
            }
        } break;
#else
        case TYPE_INT8:
            target = format("%i", _vt.data.i8);
            break;
        case TYPE_UINT8:
            target = format("%u", _vt.data.ui8);
            break;
#endif
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
        case TYPE_BINARY: {
            if (_vt.data.str) {
                target.clear();
                uint32 i = 0;
                char *p = nullptr;
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

variant &variant::operator=(const variant &rhs) {
    _vt = rhs._vt;
    return *this;
}

variant &variant::operator=(variant &&rhs) {
    _vt = std::move(rhs._vt);
    return *this;
}

}  // namespace hotplace
