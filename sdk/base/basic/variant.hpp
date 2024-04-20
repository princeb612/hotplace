/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_VARIANT__
#define __HOTPLACE_SDK_BASE_VARIANT__

#include <string.h>

#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>

namespace hotplace {

/**
 * @brief   vartype_t
 */
enum vartype_t {
    TYPE_NULL = 0,
    TYPE_VOID = TYPE_NULL,

    TYPE_BOOLEAN = 1,
    TYPE_BOOL = 2,

    TYPE_CHAR = 3,
    TYPE_INT8 = TYPE_CHAR,
    TYPE_SINT8 = TYPE_CHAR,

    TYPE_BYTE = 4,
    TYPE_UINT8 = TYPE_BYTE,

    TYPE_INT16 = 5,
    TYPE_SHORT = TYPE_INT16,
    TYPE_SINT16 = TYPE_INT16,

    TYPE_UINT16 = 6,
    TYPE_USHORT = TYPE_UINT16,
    TYPE_WORD = TYPE_UINT16,

    TYPE_INT32 = 7,
    TYPE_SINT32 = TYPE_INT32,

    TYPE_UINT32 = 8,
    TYPE_DWORD = TYPE_UINT32,

    TYPE_INT64 = 9,
    TYPE_SINT64 = TYPE_INT64,

    TYPE_UINT64 = 10,

    TYPE_INT = TYPE_INT32,
    TYPE_UINT = TYPE_UINT32,
    TYPE_LONGLONG = TYPE_INT64,
    TYPE_ULONGLONG = TYPE_UINT64,

#if defined __linux__
#if __WORDSIZE == 32
    TYPE_LONG = TYPE_INT32,
    TYPE_ULONG = TYPE_UINT32,
#elif __WORDSIZE == 64
    TYPE_LONG = TYPE_INT64,
    TYPE_ULONG = TYPE_UINT64,
#endif
#elif defined _WIN32 || defined _WIN64
    TYPE_LONG = TYPE_INT32,
    TYPE_ULONG = TYPE_UINT32,
#endif

    TYPE_INT128 = 11,
    TYPE_UINT128 = 12,
    TYPE_BASE64 = 13,
    TYPE_BASE64URL = 14,

    TYPE_NSTRING = 15,  ///<< string manipulation wo memory allocation ("abc" from source : "abcdefg" and size : 3)

    TYPE_POINTER = 20,
    TYPE_TCHAR = 21,
    TYPE_WCHAR = 22,
    TYPE_TSTRING = 23,
    TYPE_STRING = 24,
    TYPE_WSTRING = 25,
    TYPE_BSTRING = TYPE_WSTRING,

    TYPE_FLOAT = 26,  /* single precision floating point */
    TYPE_DOUBLE = 27, /* double precision floating point */
    TYPE_FP16 = 28,   /* half precision floating point */
    TYPE_FP128 = 29,  /* quadruple precision floating point */

    TYPE_DATETIME = 30,
    TYPE_BINARY = 31,
    TYPE_BLOB = TYPE_BINARY,

    TYPE_TEXT = 32,     /* specially vector<string> */
    TYPE_JBOOLEAN = 33, /* unsigned char */
    TYPE_JBYTE = 34,    /* signed char */
    TYPE_JCHAR = 35,    /* unsigned short */
    TYPE_JSTRING = 36,  /* java/lang/String */

    TYPE_INT24 = 37,
    TYPE_UINT24 = 38,

    TYPE_RESERVED = 0x1000,

    TYPE_USER = 0x10000,
};

/**
 * byte type conflict
 *
 * #if __cplusplus >= 201703L
 * enum class byte : unsigned char;
 * ...
 * #endif
 */
typedef unsigned char byte_t;
typedef unsigned int uint;

enum variant_flag_t {
    flag_free = 1 << 0,

    // fast check
    flag_bool = 1 << 1,     // bool
    flag_int = 1 << 2,      // int8~int128
    flag_float = 1 << 3,    // float, double
    flag_string = 1 << 4,   // string
    flag_binary = 1 << 5,   // binary
    flag_pointer = 1 << 6,  // pointer
    flag_user_type = 1 << 7,
};

typedef struct __variant_t {
    vartype_t type;
    union {
        bool b;
        // BOOL B; // uint32
        char c;
        char jb;
        byte_t uc;
        byte_t jbool;
        double d;
        float f;
        int i;
        uint ui;
        int8 i8;
        uint8 ui8;
        int16 i16;
        uint16 ui16;
        uint16 jc;
        int32 i32;
        uint32 ui32;
        int64 i64;
        uint64 ui64;
#if defined __SIZEOF_INT128__
        int128 i128;
        uint128 ui128;
#endif
        // long l;   ulong ul;
        // short s;   ushort us;
        void* p;
        char* str;
        byte_t* bstr;
    } data;
    uint16 size;
    uint16 flag;

    __variant_t() : type(TYPE_NULL), size(0), flag(0) { memset(&data, 0, sizeof(data)); }
} variant_t;

template <typename T>
T t_variant_to_int(variant_t const& vt) {
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
            // errorcode_t::unexpected;
            break;
    }
    return i;
}

class variant {
   public:
    variant();
    variant(const variant& source);
    variant(variant&& source);
    ~variant();

    variant_t& content();
    vartype_t type();
    uint16 size();
    uint16 flag();

    /**
     * @brief reset
     * @example
     *      vt.reset().set_bool(true);
     */
    variant& reset();

    variant& set_flag(uint8 flag);
    variant& unset_flag(uint8 flag);

    variant& set_pointer(const void* value);
    variant& set_bool(bool value);
    variant& set_int8(int8 value);
    variant& set_uint8(uint8 value);
    variant& set_int16(int16 value);
    variant& set_uint16(uint16 value);
    variant& set_int24(int32 value);    // 32/24 [0 .. 0x00ffffff]
    variant& set_uint24(uint32 value);  // 32/24 [0 .. 0x00ffffff]
    variant& set_int32(int32 value);    // 32/32 [0 .. 0xffffffff]
    variant& set_uint32(uint32 value);  // 32/32 [0 .. 0xffffffff]
    variant& set_int64(int64 value);
    variant& set_uint64(uint64 value);
#if defined __SIZEOF_INT128__
    variant& set_int128(int128 value);
    variant& set_uint128(uint128 value);
#endif
    variant& set_fp16(uint16 value);
    variant& set_fp32(float value);
    variant& set_float(float value);
    variant& set_fp64(double value);
    variant& set_double(double value);
    variant& set_str(const char* value);
    variant& set_nstr(const char* value, size_t n);
    variant& set_bstr(const unsigned char* value, size_t n);
    variant& set_user_type(vartype_t vtype, void* value);

    variant& set_str_new(const char* value);
    variant& set_strn_new(const char* value, size_t n);
    variant& set_bstr_new(const unsigned char* value, size_t n);
    variant& set_nstr_new(const char* value, size_t n);
    variant& set_binary_new(binary_t const& bin);

    int to_int() const;
    return_t to_binary(binary_t& target) const;
    return_t to_string(std::string& target) const;
    return_t dump(binary_t& target, bool change_endian) const;

    variant& copy(variant_t const& value);
    variant& move(variant_t& value);
    variant& copy(const variant& source);
    variant& move(variant& source);
    variant& operator=(const variant& source);

   protected:
    variant_t _vt;
};

}  // namespace hotplace

#endif
