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

#include <hotplace/sdk/base/types.hpp>
//#include <vector>

namespace hotplace {

/**
 * @brief   vartype_t
 * @remarks variant 에 대한 type 정의
 */
enum vartype_t {
    TYPE_NULL       = 0,
    TYPE_VOID       = TYPE_NULL,

    TYPE_BOOLEAN    = 1,    // sizeof 1
    TYPE_BOOL       = 2,    // sizeof 4

    TYPE_CHAR       = 3,
    TYPE_INT8       = TYPE_CHAR,
    TYPE_SINT8      = TYPE_CHAR,

    TYPE_BYTE       = 4,
    TYPE_UINT8      = TYPE_BYTE,

    TYPE_SHORT      = 5,
    TYPE_INT16      = TYPE_SHORT,
    TYPE_SINT16     = TYPE_SHORT,

    TYPE_USHORT     = 6,
    TYPE_WORD       = TYPE_USHORT,
    TYPE_UINT16     = TYPE_USHORT,

    TYPE_INT32      = 7,
    TYPE_SINT32     = TYPE_INT32,

    TYPE_ULONG      = 8,
    TYPE_UINT       = 8,
    TYPE_DWORD      = TYPE_ULONG,
    TYPE_UINT32     = TYPE_ULONG,

    TYPE_INT64      = 9,
    TYPE_SINT64     = TYPE_INT64,
    TYPE_LONGLONG   = TYPE_INT64,

    TYPE_ULONGLONG  = 10,
    TYPE_UINT64     = TYPE_ULONGLONG,
#if defined __linux__
#if __WORDSIZE == 32
    TYPE_LONG       = TYPE_INT32,
#elif __WORDSIZE == 64
    TYPE_LONG       = TYPE_INT64,
#endif
#elif defined _WIN32 || defined _WIN64
    TYPE_LONG       = TYPE_INT32,
#endif
    TYPE_INT        = TYPE_INT32,

    TYPE_INT128     = 11,
    TYPE_UINT128    = 12,
    TYPE_BASE64     = 13,
    TYPE_BASE64URL  = 14,

    TYPE_POINTER    = 20,
    TYPE_TCHAR      = 21,
    TYPE_WCHAR      = 22,
    TYPE_TSTRING    = 23,
    TYPE_STRING     = 24,
    TYPE_WSTRING    = 25,
    TYPE_BSTRING    = TYPE_WSTRING,

    TYPE_FLOAT      = 26,
    TYPE_DOUBLE     = 27,

    TYPE_DATETIME   = 30,
    TYPE_BINARY     = 31,
    TYPE_BLOB       = TYPE_BINARY,

    TYPE_TEXT       = 32,   /* specially vector<string> */
    TYPE_JBOOLEAN   = 33,   /* unsigned char */
    TYPE_JBYTE      = 34,   /* signed char */
    TYPE_JCHAR      = 35,   /* unsigned short */
    TYPE_JSTRING    = 36,   /* java/lang/String */

    TYPE_RESERVED   = 0x1000,

    TYPE_USER       = 0x10000,
};

/*
 * byte type conflict
 *
 * #if __cplusplus >= 201703L
 * enum class byte : unsigned char;
 * ...
 * #endif
 */
typedef unsigned char byte_t;
typedef unsigned int uint;

typedef struct _variant_t {
    vartype_t type;
    union {
        bool b;
        //BOOL B; // uint32
        char c;   char jb;
        byte_t uc;  byte_t jbool;
        double d;
        float f;
        int i;   uint ui;
        int8 i8;  uint8 ui8;
        int16 i16; uint16 ui16; uint16 jc;
        int32 i32; uint32 ui32;
        int64 i64; uint64 ui64;
#if defined __SIZEOF_INT128__
        int128 i128; uint128 ui128;
#endif
        //long l;   ulong ul;
        //short s;   ushort us;
        void*  p;
        char*  str;
        struct _bstr32 {
            uint32 size;
            byte_t* data;
        } bstr32;
    } data;
} variant_t;

#define variant_init(vt) { vt.type = TYPE_NULL; memset (&vt.data, 0, sizeof (vt.data)); }

#define variant_set_bool(vt, value) { vt.type = TYPE_BOOL; vt.data.b = (value); }
#define variant_set_int8(vt, value) { vt.type = TYPE_INT8; vt.data.i8 = (value); }
#define variant_set_uint8(vt, value) { vt.type = TYPE_UINT8; vt.data.ui8 = (value); }
#define variant_set_int16(vt, value) { vt.type = TYPE_INT16; vt.data.i16 = (value); }
#define variant_set_uint16(vt, value) { vt.type = TYPE_UINT16; vt.data.ui16 = (value); }
#define variant_set_int32(vt, value) { vt.type = TYPE_INT32; vt.data.i32 = (value); }
#define variant_set_uint32(vt, value) { vt.type = TYPE_UINT32; vt.data.ui32 = (value); }
#define variant_set_int64(vt, value) { vt.type = TYPE_INT64; vt.data.i64 = (value); }
#define variant_set_uint64(vt, value) { vt.type = TYPE_UINT64; vt.data.ui64 = (value); }
#if defined __SIZEOF_INT128__
#define variant_set_int128(vt, value) { vt.type = TYPE_INT128; vt.data.i128 = (value); }
#define variant_set_uint128(vt, value) { vt.type = TYPE_UINT128; vt.data.ui128 = (value); }
#endif
#define variant_set_float(vt, value) { vt.type = TYPE_FLOAT; vt.data.f = (value); }
#define variant_set_double(vt, value) { vt.type = TYPE_DOUBLE; vt.data.d = (value); }

#define variant_set_bool_ptr(vt, value) { vt.type = TYPE_BOOL; vt.data.b = *(bool*) (value); }
#define variant_set_int8_ptr(vt, value) { vt.type = TYPE_INT8; vt.data.i8 = *(int8*) (value); }
#define variant_set_uint8_ptr(vt, value) { vt.type = TYPE_UINT8; vt.data.ui8 = *(uint8*) (value); }
#define variant_set_int16_ptr(vt, value) { vt.type = TYPE_INT16; vt.data.i16 = *(int16*) (value); }
#define variant_set_uint16_ptr(vt, value) { vt.type = TYPE_UINT16; vt.data.ui16 = *(uint16*) (value); }
#define variant_set_int32_ptr(vt, value) { vt.type = TYPE_INT32; vt.data.i32 = *(int32*) (value); }
#define variant_set_uint32_ptr(vt, value) { vt.type = TYPE_UINT32; vt.data.ui32 = *(uint32*) (value); }
#define variant_set_int64_ptr(vt, value) { vt.type = TYPE_INT64; vt.data.i64 = *(int64*) (value); }
#define variant_set_uint64_ptr(vt, value) { vt.type = TYPE_UINT64; vt.data.ui64 = *(uint64*) (value); }
#if defined __SIZEOF_INT128__
#define variant_set_int128_ptr(vt, value) { vt.type = TYPE_INT128; vt.data.i128 = *(int128*) (value); }
#define variant_set_uint128_ptr(vt, value) { vt.type = TYPE_UINT128; vt.data.ui128 = *(uint128*) (value); }
#endif
#define variant_set_float_ptr(vt, value) { vt.type = TYPE_FLOAT; vt.data.f = *(float*) (value); }
#define variant_set_double_ptr(vt, value) { vt.type = TYPE_DOUBLE; vt.data.d = *(double*) (value); }

#define variant_set_pointer(vt, value) { vt.type = TYPE_POINTER; vt.data.p = (void*) (value); }
#define variant_set_str(vt, value) { vt.type = TYPE_STRING; vt.data.str = (char*) (value); }
#define variant_set_bstr(vt, value, size) { vt.type = TYPE_BINARY; vt.data.bstr32.data = (value); vt.data.bstr32.size = (size); }
#define variant_set(vt, vttype, value) { vt.type = vttype; vt.data.p = (void*) (value); }
// strdup
#define variant_set_str_new(vt, value) { vt.type = TYPE_STRING; vt.data.str = strdup (value); }
// strndup
#define variant_set_strn_new(vt, value, len) { vt.type = TYPE_STRING; char* p = (char*) malloc (len + 1); if (p) { strncpy (p, value, len); *(p + len) = 0; }; vt.data.str = p; }
// duplicate
#define variant_set_bstr_new(vt, value, size) { vt.type = TYPE_BINARY; void* p = malloc (size); if (p) { memcpy (p, value, size); vt.data.bstr32.data = (byte_t*) p; vt.data.bstr32.size = (size); } else { vt.data.bstr32.data = (byte_t*) nullptr; vt.data.bstr32.size = 0; } }
#define variant_free(vt) \
    { \
        switch (vt.type) { \
            case TYPE_STRING: \
            case TYPE_POINTER: \
                if (vt.data.str) { \
                    free (vt.data.str); \
                } \
                break; \
            case TYPE_BINARY: \
                if (vt.data.bstr32.data) { \
                    free (vt.data.bstr32.data); \
                } \
                break; \
            default: \
                break; \
        } \
        variant_init (vt); \
    }

} // namespace

#endif

