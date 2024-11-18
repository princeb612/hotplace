/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_BASIC_VARIANT__
#define __HOTPLACE_SDK_BASE_BASIC_VARIANT__

#include <string.h>

#include <sdk/base/basic/types.hpp>
#include <sdk/base/system/datetime.hpp>

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

    TYPE_FLOAT = 26,  /* single precision floating point */
    TYPE_DOUBLE = 27, /* double precision floating point */
    TYPE_FP16 = 28,   /* half precision floating point */
    TYPE_FP128 = 29,  /* quadruple precision floating point */

    TYPE_DATETIME = 30,
    TYPE_BINARY = 31,
    TYPE_BLOB = TYPE_BINARY,
    TYPE_BSTRING = TYPE_BINARY,

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

enum variant_control_t {
    variant_trunc = (1 << 16),
    variant_convendian = (1 << 17),
};

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
    flag_datetime = 1 << 8,  // datetime
};

union vartype_union {
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
    datetime_t* dt;
};

struct variant_t {
    vartype_t type;
    vartype_union data;
    uint16 size;
    uint16 flag;

    variant_t() : type(TYPE_NULL), size(0), flag(0) { memset(&data, 0, sizeof(data)); }
    variant_t(const variant_t& rhs) : type(TYPE_NULL), size(0), flag(0) { *this = rhs; }
    variant_t(variant_t&& rhs) : type(TYPE_NULL), size(0), flag(0) { *this = std::move(rhs); }
    ~variant_t() { clear(); }

    variant_t& operator=(const variant_t& rhs) {
        clear();

        type = rhs.type;
        if (variant_flag_t::flag_free & rhs.flag) {
            switch (rhs.type) {
                case TYPE_BINARY:
                case TYPE_NSTRING:
                    data.bstr = (unsigned char*)malloc(rhs.size + 1);
                    memcpy(data.bstr, rhs.data.bstr, rhs.size);
                    break;
                case TYPE_STRING:
                    data.str = strdup(rhs.data.str);
                    break;
                case TYPE_DATETIME:
                    data.dt = (datetime_t*)malloc(sizeof(datetime_t));
                    memcpy(data.dt, rhs.data.dt, sizeof(datetime_t));
                    break;
                default:
                    break;
            }
        } else {
            memcpy(&data, &rhs.data, sizeof(data));
        }
        size = rhs.size;
        flag = rhs.flag;

        return *this;
    }
    variant_t& operator=(variant_t&& rhs) {
        clear();

        type = rhs.type;
        memcpy(&data, &rhs.data, sizeof(data));
        size = rhs.size;
        flag = rhs.flag;
        rhs.reset();

        return *this;
    }

    variant_t& reset() {
        type = TYPE_NULL;
        memset(&data, 0, sizeof(data));
        size = 0;
        flag = 0;

        return *this;
    }
    variant_t& clear() {
        if (variant_flag_t::flag_free & flag) {
            free(data.p);
        }

        type = TYPE_NULL;
        memset(&data, 0, sizeof(data));
        size = 0;
        flag = 0;

        return *this;
    }
};

class variant {
   public:
    variant();
    variant(const void* value);
    variant(const char* value);
    variant(const char* value, size_t n);
    variant(const unsigned char* value, size_t n);
    variant(const std::string& rhs);
    variant(const binary_t& rhs);
    variant(const stream_t* rhs);
    variant(bool value);
    variant(int8 value);
    variant(uint8 value);
    variant(int16 value);
    variant(uint16 value);
    variant(int32 value);
    variant(uint32 value);
    variant(int64 value);
    variant(uint64 value);
#if defined __SIZEOF_INT128__
    variant(int128 value);
    variant(uint128 value);
#endif
    variant(float value);
    variant(double value);
    variant(const datetime_t& value);
    variant(const variant_t& rhs);
    variant(variant_t&& rhs);
    variant(const variant& rhs);
    variant(variant&& rhs);
    ~variant();

    const variant_t& content() const;
    vartype_t type() const;
    uint16 size() const;
    uint16 flag() const;

    /**
     * @brief   clear
     * @example
     *          vt.clear().set_bool(true);
     */
    variant& clear();

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
    variant& set_datetime(const datetime_t& value);
    variant& set_str(const char* value);
    variant& set_nstr(const char* value, size_t n);
    variant& set_bstr(const unsigned char* value, size_t n);
    variant& set_user_type(vartype_t vtype, void* value);

    variant& set_str_new(const char* value);
    variant& set_str_new(const std::string& value);
    variant& set_strn_new(const char* value, size_t n);
    variant& set_bstr_new(const unsigned char* value, size_t n);
    variant& set_bstr_new(const stream_t* s);
    variant& set_nstr_new(const char* value, size_t n);
    variant& set_binary_new(const binary_t& bin);

    /**
     * @brief   to string
     */
    const std::string to_str() const;
    /**
     * @brief   to hexadecimal
     */
    const std::string to_hex() const;
    /**
     * @brief   to binary
     * @param   uint32 flags [inopt] see variant_control_flag_t
     */
    const binary_t to_bin(uint32 flags = 0) const;
    /**
     * @brief   to integer
     */
    int to_int() const;
    /*
     * @brief   to binary
     * @param   binary_t& target [out]
     * @param   uint32 flags [inopt] see variant_control_flag_t
     */
    return_t to_binary(binary_t& target, uint32 flags = 0) const;
    /**
     * @brief   to string
     * @param   std::string& target [out]
     */
    return_t to_string(std::string& target) const;

    variant& operator=(const variant& source);
    variant& operator=(variant&& source);
    variant& operator=(const variant_t& source);
    variant& operator=(variant_t&& source);

   protected:
    variant_t _vt;
};

}  // namespace hotplace

#endif
