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

#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/syntax.hpp>
#include <hotplace/sdk/base/types.hpp>

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

    TYPE_SHORT = 5,
    TYPE_INT16 = TYPE_SHORT,
    TYPE_SINT16 = TYPE_SHORT,

    TYPE_USHORT = 6,
    TYPE_WORD = TYPE_USHORT,
    TYPE_UINT16 = TYPE_USHORT,

    TYPE_INT32 = 7,
    TYPE_SINT32 = TYPE_INT32,

    TYPE_ULONG = 8,
    TYPE_UINT = 8,
    TYPE_DWORD = TYPE_ULONG,
    TYPE_UINT32 = TYPE_ULONG,

    TYPE_INT64 = 9,
    TYPE_SINT64 = TYPE_INT64,
    TYPE_LONGLONG = TYPE_INT64,

    TYPE_ULONGLONG = 10,
    TYPE_UINT64 = TYPE_ULONGLONG,
#if defined __linux__
#if __WORDSIZE == 32
    TYPE_LONG = TYPE_INT32,
#elif __WORDSIZE == 64
    TYPE_LONG = TYPE_INT64,
#endif
#elif defined _WIN32 || defined _WIN64
    TYPE_LONG = TYPE_INT32,
#endif
    TYPE_INT = TYPE_INT32,

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
    flag_free = 1,
};

typedef struct __variant_t {
    vartype_t type;
    union _data {
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
    uint32 size;
    uint8 flag;

    __variant_t() : type(TYPE_NULL), size(0), flag(0) { memset(&data, 0, sizeof(data)); }
} variant_t;

#define variant_init(vt)                      \
    {                                         \
        vt.type = TYPE_NULL;                  \
        memset(&vt.data, 0, sizeof(vt.data)); \
        vt.size = 0;                          \
        vt.flag = 0;                          \
    }
#define variant_set_flag \
    (vt, flag) { vt.flag |= flag }
#define variant_unset_flag \
    (vt, flag) { vt.flag &= ~flag }

#define variant_set_bool(vt, value) \
    {                               \
        vt.type = TYPE_BOOL;        \
        vt.data.b = (value);        \
        vt.size = 0;                \
        vt.flag = 0;                \
    }
#define variant_set_int8(vt, value) \
    {                               \
        vt.type = TYPE_INT8;        \
        vt.data.i8 = (value);       \
        vt.size = 0;                \
        vt.flag = 0;                \
    }
#define variant_set_uint8(vt, value) \
    {                                \
        vt.type = TYPE_UINT8;        \
        vt.data.ui8 = (value);       \
        vt.size = 0;                 \
        vt.flag = 0;                 \
    }
#define variant_set_int16(vt, value) \
    {                                \
        vt.type = TYPE_INT16;        \
        vt.data.i16 = (value);       \
        vt.size = 0;                 \
        vt.flag = 0;                 \
    }
#define variant_set_uint16(vt, value) \
    {                                 \
        vt.type = TYPE_UINT16;        \
        vt.data.ui16 = (value);       \
        vt.size = 0;                  \
        vt.flag = 0;                  \
    }
#define variant_set_int32(vt, value) \
    {                                \
        vt.type = TYPE_INT32;        \
        vt.data.i32 = (value);       \
        vt.size = 0;                 \
        vt.flag = 0;                 \
    }
#define variant_set_uint32(vt, value) \
    {                                 \
        vt.type = TYPE_UINT32;        \
        vt.data.ui32 = (value);       \
        vt.size = 0;                  \
        vt.flag = 0;                  \
    }
#define variant_set_int64(vt, value) \
    {                                \
        vt.type = TYPE_INT64;        \
        vt.data.i64 = (value);       \
        vt.size = 0;                 \
        vt.flag = 0;                 \
    }
#define variant_set_uint64(vt, value) \
    {                                 \
        vt.type = TYPE_UINT64;        \
        vt.data.ui64 = (value);       \
        vt.size = 0;                  \
        vt.flag = 0;                  \
    }
#if defined __SIZEOF_INT128__
#define variant_set_int128(vt, value) \
    {                                 \
        vt.type = TYPE_INT128;        \
        vt.data.i128 = (value);       \
        vt.size = 0;                  \
        vt.flag = 0;                  \
    }
#define variant_set_uint128(vt, value) \
    {                                  \
        vt.type = TYPE_UINT128;        \
        vt.data.ui128 = (value);       \
        vt.size = 0;                   \
        vt.flag = 0;                   \
    }
#endif
#define variant_set_fp16(vt, value) \
    {                               \
        vt.type = TYPE_FP16;        \
        vt.data.ui16 = (value);     \
        vt.size = 0;                \
        vt.flag = 0;                \
    }
#define variant_set_fp32(vt, value) \
    {                               \
        vt.type = TYPE_FLOAT;       \
        vt.data.f = (value);        \
        vt.size = 0;                \
        vt.flag = 0;                \
    }
#define variant_set_float(vt, value) \
    {                                \
        vt.type = TYPE_FLOAT;        \
        vt.data.f = (value);         \
        vt.size = 0;                 \
        vt.flag = 0;                 \
    }
#define variant_set_fp64(vt, value) \
    {                               \
        vt.type = TYPE_DOUBLE;      \
        vt.data.d = (value);        \
        vt.size = 0;                \
        vt.flag = 0;                \
    }
#define variant_set_double(vt, value) \
    {                                 \
        vt.type = TYPE_DOUBLE;        \
        vt.data.d = (value);          \
        vt.size = 0;                  \
        vt.flag = 0;                  \
    }
#if defined __SIZEOF_INT128__
#define variant_set_fp128(vt, value) \
    {                                \
        vt.type = TYPE_FP128;        \
        vt.data.ui128 = (value);     \
        vt.size = 0;                 \
        vt.flag = 0;                 \
    }
#endif

#define variant_set_bool_ptr(vt, value) \
    {                                   \
        vt.type = TYPE_BOOL;            \
        vt.data.b = *(bool*)(value);    \
        vt.size = 0;                    \
        vt.flag = 0;                    \
    }
#define variant_set_int8_ptr(vt, value) \
    {                                   \
        vt.type = TYPE_INT8;            \
        vt.data.i8 = *(int8*)(value);   \
        vt.size = 0;                    \
        vt.flag = 0;                    \
    }
#define variant_set_uint8_ptr(vt, value) \
    {                                    \
        vt.type = TYPE_UINT8;            \
        vt.data.ui8 = *(uint8*)(value);  \
        vt.size = 0;                     \
        vt.flag = 0;                     \
    }
#define variant_set_int16_ptr(vt, value) \
    {                                    \
        vt.type = TYPE_INT16;            \
        vt.data.i16 = *(int16*)(value);  \
        vt.size = 0;                     \
        vt.flag = 0;                     \
    }
#define variant_set_uint16_ptr(vt, value) \
    {                                     \
        vt.type = TYPE_UINT16;            \
        vt.data.ui16 = *(uint16*)(value); \
        vt.size = 0;                      \
        vt.flag = 0;                      \
    }
#define variant_set_int32_ptr(vt, value) \
    {                                    \
        vt.type = TYPE_INT32;            \
        vt.data.i32 = *(int32*)(value);  \
        vt.size = 0;                     \
        vt.flag = 0;                     \
    }
#define variant_set_uint32_ptr(vt, value) \
    {                                     \
        vt.type = TYPE_UINT32;            \
        vt.data.ui32 = *(uint32*)(value); \
        vt.size = 0;                      \
        vt.flag = 0;                      \
    }
#define variant_set_int64_ptr(vt, value) \
    {                                    \
        vt.type = TYPE_INT64;            \
        vt.data.i64 = *(int64*)(value);  \
        vt.size = 0;                     \
        vt.flag = 0;                     \
    }
#define variant_set_uint64_ptr(vt, value) \
    {                                     \
        vt.type = TYPE_UINT64;            \
        vt.data.ui64 = *(uint64*)(value); \
        vt.size = 0;                      \
        vt.flag = 0;                      \
    }
#if defined __SIZEOF_INT128__
#define variant_set_int128_ptr(vt, value) \
    {                                     \
        vt.type = TYPE_INT128;            \
        vt.data.i128 = *(int128*)(value); \
        vt.size = 0;                      \
        vt.flag = 0;                      \
    }
#define variant_set_uint128_ptr(vt, value)  \
    {                                       \
        vt.type = TYPE_UINT128;             \
        vt.data.ui128 = *(uint128*)(value); \
        vt.size = 0;                        \
        vt.flag = 0;                        \
    }
#endif
#define variant_set_float_ptr(vt, value) \
    {                                    \
        vt.type = TYPE_FLOAT;            \
        vt.data.f = *(float*)(value);    \
        vt.size = 0;                     \
        vt.flag = 0;                     \
    }
#define variant_set_double_ptr(vt, value) \
    {                                     \
        vt.type = TYPE_DOUBLE;            \
        vt.data.d = *(double*)(value);    \
        vt.size = 0;                      \
        vt.flag = 0;                      \
    }

#define variant_set_pointer(vt, value) \
    {                                  \
        vt.type = TYPE_POINTER;        \
        vt.data.p = (void*)(value);    \
        vt.size = 0;                   \
        vt.flag = 0;                   \
    }
#define variant_set_str(vt, value)    \
    {                                 \
        vt.type = TYPE_STRING;        \
        vt.data.str = (char*)(value); \
        vt.size = 0;                  \
        vt.flag = 0;                  \
    }
#define variant_set_nstr(vt, value, n) \
    {                                  \
        vt.type = TYPE_NSTRING;        \
        vt.data.str = (value);         \
        vt.size = (n);                 \
        vt.flag = 0;                   \
    }
#define variant_set_bstr(vt, value, n)   \
    {                                    \
        vt.type = TYPE_BINARY;           \
        vt.data.bstr = (byte_t*)(value); \
        vt.size = (n);                   \
        vt.flag = 0;                     \
    }
#define variant_set(vt, vttype, value) \
    {                                  \
        vt.type = vttype;              \
        vt.data.p = (void*)(value);    \
        vt.flag = 0;                   \
    }
// strdup
#define variant_set_str_new(vt, value)       \
    {                                        \
        vt.type = TYPE_STRING;               \
        vt.data.str = strdup(value);         \
        vt.size = 0;                         \
        vt.flag = variant_flag_t::flag_free; \
    }
// strndup
#define variant_set_strn_new(vt, value, n)   \
    {                                        \
        vt.type = TYPE_STRING;               \
        vt.size = 0;                         \
        char* p = (char*)malloc((n) + 1);    \
        if (p) {                             \
            strncpy(p, value, (n));          \
            *(p + (n)) = 0;                  \
        };                                   \
        vt.data.str = p;                     \
        vt.flag = variant_flag_t::flag_free; \
    }
// duplicate
#define variant_set_bstr_new(vt, value, n)   \
    {                                        \
        vt.type = TYPE_BINARY;               \
        vt.size = 0;                         \
        void* p = nullptr;                   \
        if (n) {                             \
            p = malloc(n);                   \
            if (p) {                         \
                memcpy(p, value, (n));       \
                vt.size = (n);               \
            };                               \
        };                                   \
        vt.data.bstr = (byte_t*)p;           \
        vt.flag = variant_flag_t::flag_free; \
    }
// strndup
#define variant_set_nstr_new(vt, value, n)   \
    {                                        \
        vt.type = TYPE_NSTRING;              \
        vt.size = (n);                       \
        char* p = nullptr;                   \
        if (n) {                             \
            p = (char*)malloc((n) + 1);      \
            if (p) {                         \
                strncpy(p, value, (n));      \
                *(p + (n)) = 0;              \
            };                               \
        };                                   \
        vt.data.str = p;                     \
        vt.flag = variant_flag_t::flag_free; \
    }
#define variant_set_binary_new(vt, bin)         \
    {                                           \
        vt.type = TYPE_BINARY;                  \
        vt.size = bin.size();                   \
        void* p = nullptr;                      \
        if (bin.size()) {                       \
            p = malloc(bin.size());             \
            if (p) {                            \
                memcpy(p, &bin[0], bin.size()); \
            };                                  \
        } else {                                \
            vt.size = 0;                        \
        };                                      \
        vt.data.bstr = (byte_t*)p;              \
        vt.flag = variant_flag_t::flag_free;    \
    }

return_t variant_copy(variant_t* target, const variant_t* source);
return_t variant_move(variant_t* target, variant_t* source);
void variant_free(variant_t& vt);
return_t variant_binary(variant_t const& vt, binary_t& target);
return_t variant_string(variant_t const& vt, std::string& target);

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

}  // namespace hotplace

#endif
