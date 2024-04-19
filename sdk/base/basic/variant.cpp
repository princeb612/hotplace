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

#include <ostream>
#include <sdk/base/basic/variant.hpp>
#include <sdk/base/system/types.hpp>

namespace hotplace {

variant::variant() {}

variant::variant(const variant& source) { copy(source); }

variant::variant(variant&& source) { move(source); }

variant::~variant() {
    if (variant_flag_t::flag_free & _vt.flag) {
        free(_vt.data.p);
    }
}

variant_t& variant::content() { return _vt; }

vartype_t variant::type() { return _vt.type; }

uint16 variant::size() { return _vt.size; }

uint16 variant::flag() { return _vt.flag; }

/**
 * @brief reset
 * @example
 *      vt.reset().set_bool(true);
 */
variant& variant::reset() {
    if (variant_flag_t::flag_free & _vt.flag) {
        free(_vt.data.p);
    }

    _vt.type = TYPE_NULL;
    memset(&_vt.data, 0, RTL_FIELD_SIZE(variant_t, data));
    _vt.size = 0;
    _vt.flag = 0;
    return *this;
}

variant& variant::set_flag(uint8 flag) {
    _vt.flag |= flag;
    return *this;
}

variant& variant::unset_flag(uint8 flag) {
    _vt.flag &= ~flag;
    return *this;
}

variant& variant::set_pointer(const void* value) {
    _vt.type = TYPE_POINTER;
    _vt.data.p = (void*)value;
    _vt.size = sizeof(void*);
    _vt.flag = flag_pointer;
    return *this;
}

variant& variant::set_bool(bool value) {
    _vt.type = TYPE_BOOL;
    _vt.data.b = (value);
    _vt.size = sizeof(bool);
    _vt.flag = flag_bool;
    return *this;
}

variant& variant::set_int8(int8 value) {
    _vt.type = TYPE_INT8;
    _vt.data.i8 = (value);
    _vt.size = sizeof(int8);
    _vt.flag = flag_int;
    return *this;
}

variant& variant::set_uint8(uint8 value) {
    _vt.type = TYPE_UINT8;
    _vt.data.ui8 = (value);
    _vt.size = sizeof(uint8);
    _vt.flag = flag_int;
    return *this;
}

variant& variant::set_int16(int16 value) {
    _vt.type = TYPE_INT16;
    _vt.data.i16 = (value);
    _vt.size = sizeof(uint16);
    _vt.flag = flag_int;
    return *this;
}

variant& variant::set_uint16(uint16 value) {
    _vt.type = TYPE_UINT16;
    _vt.data.ui16 = (value);
    _vt.size = sizeof(uint16);
    _vt.flag = flag_int;
    return *this;
}

variant& variant::set_int24(int32 value) {
    _vt.type = TYPE_INT24;
    _vt.data.i32 = (value & 0x00ffffff);
    _vt.size = 3;
    _vt.flag = flag_int;
    return *this;
}

variant& variant::set_uint24(uint32 value) {
    _vt.type = TYPE_UINT24;
    _vt.data.ui32 = (value & 0x00ffffff);
    _vt.size = 3;
    _vt.flag = flag_int;
    return *this;
}

variant& variant::set_int32(int32 value) {
    _vt.type = TYPE_INT32;
    _vt.data.i32 = (value);
    _vt.size = sizeof(int32);
    _vt.flag = flag_int;
    return *this;
}

variant& variant::set_uint32(uint32 value) {
    _vt.type = TYPE_UINT32;
    _vt.data.ui32 = (value);
    _vt.size = sizeof(uint32);
    _vt.flag = flag_int;
    return *this;
}

variant& variant::set_int64(int64 value) {
    _vt.type = TYPE_INT64;
    _vt.data.i64 = (value);
    _vt.size = sizeof(int64);
    _vt.flag = flag_int;
    return *this;
}

variant& variant::set_uint64(uint64 value) {
    _vt.type = TYPE_UINT64;
    _vt.data.ui64 = (value);
    _vt.size = sizeof(uint64);
    _vt.flag = flag_int;
    return *this;
}

#if defined __SIZEOF_INT128__
variant& variant::set_int128(int128 value) {
    _vt.type = TYPE_INT128;
    _vt.data.i128 = (value);
    _vt.size = sizeof(int128);
    _vt.flag = flag_int;
    return *this;
}

variant& variant::set_uint128(uint128 value) {
    _vt.type = TYPE_UINT128;
    _vt.data.ui128 = (value);
    _vt.size = sizeof(uint128);
    _vt.flag = flag_int;
    return *this;
}
#endif

variant& variant::set_fp16(uint16 value) {
    _vt.type = TYPE_FP16;
    _vt.data.ui16 = (value);
    _vt.size = sizeof(uint16);
    _vt.flag = flag_float;
    return *this;
}

variant& variant::set_fp32(float value) {
    _vt.type = TYPE_FLOAT;
    _vt.data.f = (value);
    _vt.size = sizeof(float);
    _vt.flag = flag_float;
    return *this;
}

variant& variant::set_float(float value) { return set_fp32(value); }

variant& variant::set_fp64(double value) {
    _vt.type = TYPE_DOUBLE;
    _vt.data.d = (value);
    _vt.size = sizeof(double);
    _vt.flag = flag_float;
    return *this;
}

variant& variant::set_double(double value) { return set_fp64(value); }

variant& variant::set_str(const char* value) {
    _vt.type = TYPE_STRING;
    _vt.data.str = (char*)value;
    _vt.size = 0;
    _vt.flag = flag_string;
    return *this;
}

variant& variant::set_nstr(const char* value, size_t n) {
    _vt.type = TYPE_NSTRING;
    _vt.data.str = (char*)value;
    _vt.size = n;
    _vt.flag = flag_string;
    return *this;
}

variant& variant::set_bstr(const unsigned char* value, size_t n) {
    _vt.type = TYPE_BINARY;
    _vt.data.bstr = (unsigned char*)value;
    _vt.size = n;
    _vt.flag = flag_binary;
    return *this;
}

variant& variant::set_user_type(vartype_t vtype, void* value) {
    _vt.type = vtype;
    _vt.data.p = value;
    _vt.size = 0;
    _vt.flag = flag_user_type;
    return *this;
}

variant& variant::set_str_new(const char* value) {
    _vt.type = TYPE_STRING;
    _vt.size = 0;
    _vt.flag = flag_string;
    char* p = nullptr;
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

variant& variant::set_strn_new(const char* value, size_t n) {
    _vt.type = TYPE_STRING;
    _vt.size = 0;
    _vt.flag = flag_string;
    char* p = nullptr;
    if (n) {
        p = (char*)malloc(n + 1);
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

variant& variant::set_bstr_new(const unsigned char* value, size_t n) {
    _vt.type = TYPE_BINARY;
    _vt.size = 0;
    _vt.flag = flag_binary;
    unsigned char* p = nullptr;
    if (n) {
        p = (unsigned char*)malloc(n + 1);
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

variant& variant::set_nstr_new(const char* value, size_t n) {
    _vt.type = TYPE_NSTRING;
    _vt.size = 0;
    _vt.flag = flag_string;
    char* p = nullptr;
    if (n) {
        p = (char*)malloc(n + 1);
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

variant& variant::set_binary_new(binary_t const& bin) {
    _vt.type = TYPE_BINARY;
    _vt.size = 0;
    _vt.flag = flag_binary;
    unsigned char* p = nullptr;
    size_t n = bin.size();
    if (n) {
        p = (unsigned char*)malloc(n + 1);
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

int variant::to_int() const { return t_variant_to_int<int>(_vt); }

return_t variant::to_binary(binary_t& target) const {
    return_t ret = errorcode_t::success;

    if (TYPE_BINARY == _vt.type) {
        target.resize(_vt.size);
        memcpy(&target[0], _vt.data.bstr, _vt.size);
    } else {
        ret = errorcode_t::mismatch;
    }
    return ret;
}
return_t variant::to_string(std::string& target) const {
    return_t ret = errorcode_t::success;

    if (_vt.data.str) {
        if (TYPE_STRING == _vt.type) {
            target = _vt.data.str;
        } else if (TYPE_NSTRING == _vt.type) {
            target.assign(_vt.data.str, _vt.size);
        } else if (TYPE_BINARY == _vt.type) {
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
        } else {
            ret = errorcode_t::mismatch;
        }
    } else {
        target.clear();
    }
    return ret;
}

return_t variant::dump(binary_t& target, bool change_endian) const {
    return_t ret = errorcode_t::success;
    byte_t* p = nullptr;
    switch (_vt.type) {
        case TYPE_INT8:
        case TYPE_UINT8:
            target.insert(target.end(), _vt.data.ui8);
            break;
        case TYPE_INT16:
        case TYPE_UINT16:
            if (change_endian) {
                binsert<uint16>(target, _vt.data.ui16, htons);
            } else {
                binsert<uint16>(target, _vt.data.ui16);
            }
            break;
        case TYPE_INT24:
        case TYPE_UINT24: {
            uint24_t temp;
            uint32_24(temp, _vt.data.ui32);
            target.insert(target.end(), temp.data, temp.data + RTL_FIELD_SIZE(uint24_t, data));
        } break;
        case TYPE_INT32:
        case TYPE_UINT32:
            if (change_endian) {
                binsert<uint32>(target, _vt.data.ui32, htonl);
            } else {
                binsert<uint32>(target, _vt.data.ui32);
            }
            break;
        case TYPE_INT64:
        case TYPE_UINT64:
            if (change_endian) {
                binsert<uint64>(target, _vt.data.ui64, hton64);
            } else {
                binsert<uint64>(target, _vt.data.ui64);
            }
            break;
        case TYPE_INT128:
        case TYPE_UINT128:
            if (change_endian) {
                binsert<uint128>(target, _vt.data.ui128, hton128);
            } else {
                binsert<uint128>(target, _vt.data.ui128);
            }
            break;
        case TYPE_STRING:
        case TYPE_BINARY:
            target.insert(target.end(), _vt.data.bstr, _vt.data.bstr + _vt.size);
            break;
        default:
            // if necessary, ...
            break;
    }
    return ret;
}

variant& variant::copy(variant_t const& value) {
    __try2 {
        reset();

        if (variant_flag_t::flag_free & value.flag) {
            switch (value.type) {
                case TYPE_BINARY:
                    set_bstr_new(value.data.bstr, value.size);
                    break;
                case TYPE_NSTRING:
                    set_nstr_new(value.data.str, value.size);
                    break;
                case TYPE_STRING:
                    set_str_new(value.data.str);
                    break;
                default:
                    throw;
                    break;
            }
        } else {
            memcpy(&_vt, &value, sizeof(variant_t));
        }
    }
    __finally2 {
        // do nothing
    }
    return *this;
}

variant& variant::move(variant_t& value) {
    reset();

    memcpy(&_vt, &value, sizeof(variant_t));  // copy including type and flag
    memset(&value, 0, sizeof(variant_t));

    return *this;
}

variant& variant::copy(const variant& source) { return copy(source._vt); }

variant& variant::move(variant& source) { return move(source._vt); }

variant& variant::operator=(const variant& source) { return copy(source); }

}  // namespace hotplace
